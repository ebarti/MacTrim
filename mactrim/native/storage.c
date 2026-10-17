/* Read-only streaming aggregation on the system FTS traversal library.
 * No file contents are opened. Presentation boundaries never prune measurement.
 */
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include <errno.h>
#include <fts.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { ENTER=1, UPDATE, FINISH, DISCOVER, PUBLISH };
enum { MEASURED=0, SKIPPED, PARTIAL, DENIED };
enum { VIRTUAL=1, DATA_ALIAS, STATE, CLOUD, MOUNT, ALIAS, SYMLINK, SPECIAL, HARDLINK, REASONS };
enum { LINKED=1, REUSED=2, COLLAPSED=4 };
typedef struct Record {
    uint64_t id, parent, alias;
    uint64_t dev, ino, mode, stat_size, mtime_ns, ctime_ns;
    uint64_t logical, allocated, entries, direct_files, own_logical, own_allocated;
    uint64_t modified7, modified30, created7, newest_ns;
    uint64_t visited, denied, excluded, changed, reused;
    uint64_t reasons[REASONS];
    uint32_t status, reason, flags, depth;
    int32_t error;
    const char *path, *error_path;
} Record;
typedef int (*Callback)(int, Record *, void *);
typedef struct Cell { uint64_t dev, ino, owner; int used; } Cell;
typedef struct Map { Cell *cells; size_t size, count; } Map;
typedef struct Frame {
    struct Frame *parent, *owner;
    Record r;
    char *path, *first_error;
    int retained, first_errno;
} Frame;
typedef struct Scan {
    Callback callback; void *context; FTS *fts; Frame *active;
    Map directories, links;
    const char *root; const char * const *exclusions; size_t exclusion_count;
    uint64_t next_id, visited, denied, excluded, changed, reused, reasons[REASONS];
    double now, last_publish;
    int lazy, cancelled, failed;
} Scan;

uint32_t mactrim_storage_abi(void) { return 1; }
uint32_t mactrim_storage_record_size(void) { return sizeof(Record); }
static uint64_t hash(uint64_t a, uint64_t b) {
    uint64_t x=a ^ (b + UINT64_C(0x9e3779b97f4a7c15));
    x=(x^(x>>30))*UINT64_C(0xbf58476d1ce4e5b9);
    x=(x^(x>>27))*UINT64_C(0x94d049bb133111eb); return x^(x>>31);
}
static int resize(Map *m) {
    size_t n=m->size ? m->size*2 : 1024;
    Cell *p=calloc(n,sizeof(*p)); if (!p) return -1;
    for (size_t j=0;j<m->size;j++) if (m->cells[j].used) {
        Cell c=m->cells[j]; size_t i=hash(c.dev,c.ino)&(n-1);
        while(p[i].used) i=(i+1)&(n-1); p[i]=c;
    }
    free(m->cells); m->cells=p; m->size=n; return 0;
}
/* Return an existing owner or insert this owner; 0 means allocation failure. */
static uint64_t owner(Map *m,uint64_t dev,uint64_t ino,uint64_t id,int *found) {
    if ((!m->size || (m->count+1)*10>m->size*7) && resize(m)) return 0;
    size_t i=hash(dev,ino)&(m->size-1);
    while(m->cells[i].used) {
        if(m->cells[i].dev==dev && m->cells[i].ino==ino) { *found=1; return m->cells[i].owner; }
        i=(i+1)&(m->size-1);
    }
    m->cells[i]=(Cell){dev,ino,id,1}; m->count++; *found=0; return id;
}
static double monotonic(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9;
}
static uint64_t mtime_ns(const struct stat *s) {
#ifdef __APPLE__
    return (uint64_t)s->st_mtimespec.tv_sec*1000000000+s->st_mtimespec.tv_nsec;
#else
    return (uint64_t)s->st_mtim.tv_sec*1000000000+s->st_mtim.tv_nsec;
#endif
}
static uint64_t ctime_ns(const struct stat *s) {
#ifdef __APPLE__
    return (uint64_t)s->st_ctimespec.tv_sec*1000000000+s->st_ctimespec.tv_nsec;
#else
    return (uint64_t)s->st_ctim.tv_sec*1000000000+s->st_ctim.tv_nsec;
#endif
}
static int dataless(const struct stat *s) {
#ifdef __APPLE__
    return !!(s->st_flags & 0x40000000);
#else
    (void)s; return 0;
#endif
}
static void metadata(Record *r,const struct stat *s) {
    r->dev=s->st_dev; r->ino=s->st_ino; r->mode=s->st_mode; r->stat_size=s->st_size;
    r->mtime_ns=mtime_ns(s); r->ctime_ns=ctime_ns(s);
}
static int within(const char *p,const char *r) {
    size_t n=strlen(r); return !strcmp(r,"/") || (!strncmp(p,r,n) && (!p[n] || p[n]=='/'));
}
static int collapse(const char *name,unsigned depth) {
    static const char *names[]={"node_modules",".venv","venv",".tox",".nox","__pypackages__",NULL};
    if(depth>8) return 1;
    for(int i=0;names[i];i++) if(!strcmp(name,names[i])) return 1;
    return 0;
}
static int front_door(const char *p) {
    static const char *names[]={"/Users","/Applications","/Library","/private","/usr","/System","/bin","/sbin","/opt",NULL};
    for(int i=0;names[i];i++) if(!strcmp(p,names[i])) return 1;
    return 0;
}
static void counters(Scan *s,Record *r) {
    r->visited=s->visited; r->denied=s->denied; r->excluded=s->excluded;
    r->changed=s->changed; r->reused=s->reused; memcpy(r->reasons,s->reasons,sizeof(s->reasons));
}
static int emit(Scan *s,int kind,Record *r) {
    counters(s,r); int result=s->callback(kind,r,s->context);
    if(result==2) s->cancelled=1;
    return result;
}
static void exclude(Scan *s,Frame *f,int reason) {
    f->r.status=SKIPPED; f->r.reason=reason; s->excluded++; s->reasons[reason]++;
}
static void error(Scan *s,Frame *f,int value,const char *path) {
    s->denied++;
    if(f->r.status!=DENIED) f->r.status=(value==EACCES || value==EPERM) ? DENIED : PARTIAL;
    if(!f->first_error) { f->first_error=strdup(path); f->first_errno=value; }
    f->r.error=value;
}
static void add(Scan *s,uint64_t *p,uint64_t value) {
    if(UINT64_MAX-*p<value) s->failed=1; else *p+=value;
}
static void sums(Scan *s,Record *p,const Record *c) {
    add(s,&p->logical,c->logical); add(s,&p->allocated,c->allocated); add(s,&p->entries,c->entries);
    add(s,&p->modified7,c->modified7); add(s,&p->modified30,c->modified30); add(s,&p->created7,c->created7);
    if(c->newest_ns>p->newest_ns) p->newest_ns=c->newest_ns;
}
/* Snapshot the active chain only, once per heartbeat. No per-file Python calls. */
static void publish(Scan *s,int force) {
    double now=monotonic(); if(!force && now-s->last_publish<0.15) return;
    s->last_publish=now; Record below={0}, selected={0}; int have=0;
    for(Frame *f=s->active;f;f=f->parent) {
        Record r=f->r; sums(s,&r,&below); r.path=f->path;
        if(f->retained) { emit(s,UPDATE,&r); if(!have) { selected=r; have=1; } }
        below=r;
    }
    if(have) emit(s,PUBLISH,&selected);
}
static int discover(Scan *s,Frame *f) {
    if(!f->retained || (f->r.flags & (COLLAPSED|REUSED)) || f->r.status!=MEASURED) return 0;
    errno=0; FTSENT *list=fts_children(s->fts,0);
    if(!list && errno) { error(s,f,errno,f->path); return 0; }
    for(FTSENT *p=list;p && !s->cancelled;p=p->fts_link) {
        if(p->fts_info!=FTS_D && p->fts_info!=FTS_DNR) continue;
        p->fts_number=++s->next_id;
        size_t n=strlen(f->path)+strlen(p->fts_name)+2;
        char *path=malloc(n); if(!path) return -1;
        strcpy(path,f->path); if(strcmp(path,"/")) strcat(path,"/"); strcat(path,p->fts_name);
        Record r={0}; r.id=p->fts_number; r.parent=f->r.id; r.path=path; r.depth=f->r.depth+1;
        if(p->fts_statp) metadata(&r,p->fts_statp);
        if(s->lazy && collapse(p->fts_name,r.depth)) r.flags|=COLLAPSED;
        emit(s,DISCOVER,&r); free(path);
    }
    return 0;
}
static Frame *enter(Scan *s,FTSENT *p) {
    Frame *f=calloc(1,sizeof(*f)); if(!f) return NULL;
    f->parent=p->fts_level ? p->fts_parent->fts_pointer : NULL;
    f->path=strdup(p->fts_path); if(!f->path) { free(f); return NULL; }
    f->retained=!f->parent || (f->parent->retained && !(f->parent->r.flags & COLLAPSED));
    f->r.depth=p->fts_level; f->r.path=f->path;
    if(f->retained) {
        f->r.id=p->fts_number ? (uint64_t)p->fts_number : ++s->next_id;
        f->r.parent=f->parent ? f->parent->r.id : 0; f->owner=f;
        if(s->lazy && p->fts_level && collapse(p->fts_name,p->fts_level)) f->r.flags|=COLLAPSED;
    } else f->owner=f->parent->owner;
    if(p->fts_statp) metadata(&f->r,p->fts_statp);
    p->fts_pointer=f; s->active=f; s->visited++;
    int skip=0;
    if(!strcmp(f->path,"/dev") || !strcmp(f->path,"/proc") || !strcmp(f->path,"/sys") || !strcmp(f->path,"/private/dev")) skip=VIRTUAL;
    else if(!strcmp(s->root,"/") && !strcmp(f->path,"/System/Volumes/Data")) skip=DATA_ALIAS;
    for(size_t i=0;!skip && i<s->exclusion_count;i++) if(within(f->path,s->exclusions[i])) skip=STATE;
    if(!skip && p->fts_statp && dataless(p->fts_statp)) skip=CLOUD;
    if(!skip && f->parent && f->r.dev!=f->parent->r.dev && !( !strcmp(s->root,"/") && front_door(f->path))) skip=MOUNT;
    if(!skip) {
        int found=0; uint64_t old=owner(&s->directories,f->r.dev,f->r.ino,f->owner->r.id,&found);
        if(!old) { s->failed=1; return f; }
        if(found) { skip=ALIAS; f->r.alias=old; f->owner->r.flags|=LINKED; }
    }
    if(skip) exclude(s,f,skip);
    else if(p->fts_info==FTS_DNR || !(f->r.mode & 0444) || !(f->r.mode & 0111)) error(s,f,p->fts_errno ? p->fts_errno : EACCES,f->path);
    if(f->retained && emit(s,ENTER,&f->r)==1 && f->r.status==MEASURED) {
        f->r.flags|=REUSED; s->reused+=f->r.entries;
    }
    if(skip || f->r.status!=MEASURED || (f->r.flags & REUSED)) fts_set(s->fts,p,FTS_SKIP);
    else {
        f->r.logical=f->r.own_logical=f->r.stat_size;
        f->r.allocated=f->r.own_allocated=(uint64_t)p->fts_statp->st_blocks*512;
        f->r.entries=1;
        f->r.newest_ns=f->r.mtime_ns;
        if(discover(s,f)) s->failed=1;
    }
    return f;
}
static void finish(Scan *s,FTSENT *p) {
    Frame *f=p->fts_pointer; if(!f) return;
    if(f->r.status==MEASURED && !(f->r.flags & REUSED)) {
        struct stat st;
        if(lstat(f->path,&st)) error(s,f,errno,f->path);
        else if((uint64_t)st.st_dev!=f->r.dev || (uint64_t)st.st_ino!=f->r.ino ||
                (uint64_t)st.st_mode!=f->r.mode || (uint64_t)st.st_size!=f->r.stat_size ||
                mtime_ns(&st)!=f->r.mtime_ns || ctime_ns(&st)!=f->r.ctime_ns) {
            f->r.status=PARTIAL; s->changed++; f->r.error=ESTALE;
        }
    }
    if(f->retained) {
        if((f->r.flags & COLLAPSED) && f->first_error) { f->r.error=f->first_errno; f->r.error_path=f->first_error; }
        emit(s,FINISH,&f->r);
    }
    if(f->parent) {
        sums(s,&f->parent->r,&f->r);
        if(f->r.status==PARTIAL || f->r.status==DENIED) f->parent->r.status=PARTIAL;
        if(f->first_error && !f->parent->first_error) { f->parent->first_error=strdup(f->first_error); f->parent->first_errno=f->first_errno; }
    }
    s->active=f->parent; p->fts_pointer=NULL; free(f->path); free(f->first_error); free(f);
}
int mactrim_storage_scan(const char *root,const char * const *exclusions,size_t count,int lazy,Callback callback,void *context) {
    Scan s={0}; s.root=root; s.exclusions=exclusions; s.exclusion_count=count; s.lazy=lazy;
    s.callback=callback; s.context=context; s.now=time(NULL);
    struct stat st; if(lstat(root,&st) || !S_ISDIR(st.st_mode)) return -2;
#ifdef __APPLE__
    int prevent=1; (void)sysctlbyname("vfs.nspace.prevent_materialization",NULL,NULL,&prevent,sizeof(prevent));
#endif
    char *paths[]={(char *)root,NULL};
    s.fts=fts_open(paths,FTS_PHYSICAL|FTS_NOCHDIR,NULL); if(!s.fts) return -2;
    FTSENT *p;
    while(!s.cancelled && !s.failed) {
        errno=0; p=fts_read(s.fts); if(!p) { if(errno) s.failed=1; break; }
        if(p->fts_info==FTS_D || p->fts_info==FTS_DNR) {
            Frame *f=enter(&s,p); if(!f) { s.failed=1; break; }
            publish(&s, p->fts_level==0);
            if(p->fts_info==FTS_DNR) finish(&s,p);
        } else if(p->fts_info==FTS_DP) {
            finish(&s,p); publish(&s,0);
        } else {
            Frame *f=p->fts_parent->fts_pointer; if(!f) { s.failed=1; break; }
            s.visited++; f->r.entries++; f->r.direct_files++;
            if(p->fts_info==FTS_ERR || p->fts_info==FTS_NS || p->fts_info==FTS_DC) error(&s,f,p->fts_errno ? p->fts_errno : EIO,p->fts_path);
            else if(!S_ISREG(p->fts_statp->st_mode) || dataless(p->fts_statp)) {
                int reason=dataless(p->fts_statp) ? CLOUD : S_ISLNK(p->fts_statp->st_mode) ? SYMLINK : SPECIAL;
                s.excluded++; s.reasons[reason]++;
            } else {
                int duplicate=0;
                if(p->fts_statp->st_nlink>1) {
                    f->owner->r.flags|=LINKED;
                    if(!owner(&s.links,p->fts_statp->st_dev,p->fts_statp->st_ino,f->owner->r.id,&duplicate)) { s.failed=1; break; }
                }
                if(duplicate) { s.excluded++; s.reasons[HARDLINK]++; }
                else {
                    uint64_t logical=p->fts_statp->st_size, allocated=(uint64_t)p->fts_statp->st_blocks*512;
                    add(&s,&f->r.logical,logical); add(&s,&f->r.allocated,allocated);
                    add(&s,&f->r.own_logical,logical); add(&s,&f->r.own_allocated,allocated);
                    uint64_t modified_ns=mtime_ns(p->fts_statp);
                    if(modified_ns>f->r.newest_ns) f->r.newest_ns=modified_ns;
                    double modified=mtime_ns(p->fts_statp)/1e9;
                    if(modified>=s.now-7*86400) f->r.modified7+=allocated;
                    if(modified>=s.now-30*86400) f->r.modified30+=allocated;
#ifdef __APPLE__
                    if(p->fts_statp->st_birthtimespec.tv_sec>=s.now-7*86400) f->r.created7+=allocated;
#endif
                }
            }
            publish(&s,0);
        }
    }
    /* Publish observed lower bounds before freeing an interrupted active chain. */
    if(s.cancelled || s.failed) publish(&s,1);
    while(s.active) { Frame *f=s.active; s.active=f->parent; free(f->path); free(f->first_error); free(f); }
    fts_close(s.fts); free(s.directories.cells); free(s.links.cells);
    return s.failed ? -1 : s.cancelled ? 1 : 0;
}

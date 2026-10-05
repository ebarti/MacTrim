import unittest
from unittest.mock import patch
from tests import test_ui as fixtures
from mactrim.storage import complete

try:
    from mactrim.ui import index_save_status, MacTrimApp
    from textual.widgets import Static
except ImportError:
    MacTrimApp = None


@unittest.skipIf(MacTrimApp is None, 'Native UI requires the isolated Textual project environment')
class SaveStatusTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NativeUITests.asyncSetUp
    asyncTearDown = fixtures.NativeUITests.asyncTearDown
    app = fixtures.NativeUITests.app

    async def test_finished_partial_scan_displays_actual_persistence_result(self):
        node = complete(self.data)
        node.status = 'partial'
        app = self.app(initial_tab='storage')
        with patch.object(app, 'storage_worker'), patch.object(app, 'history_worker'):
            async with app.run_test(size=(140, 44)) as pilot:
                for saved, expected in [
                    ({'stored': True, 'complete_index': True, 'reusable': True}, 'INDEX SAVED'),
                    ({'stored': True, 'complete_index': True, 'reusable': False}, 'OBSERVATION SAVED'),
                    ({'stored': True, 'complete_index': False, 'reusable': False}, 'TOTALS SAVED ONLY'),
                    ({'stored': False, 'reason': 'Save error'}, 'INDEX NOT SAVED'),
                ]:
                    node.refresh = {'cache': saved, 'mode': 'full'}
                    app.storage_update(node, app.storage_generation, True)
                    await pilot.pause(.05)
                    footer = str(app.query_one('#storage-status', Static).content)
                    summary = str(app.query_one('#storage-summary', Static).content)
                    self.assertIn('Scan finished (PARTIAL)', footer)
                    self.assertIn(expected, footer)
                    self.assertIn(expected, summary)
                    self.assertFalse(app.storage_measuring)

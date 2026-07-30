from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ysu_net_watch.ui import select_menu


class TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class MenuTests(unittest.TestCase):
    def test_interactive_menu_clears_viewport_before_saving_origin(self) -> None:
        output = TtyBuffer()
        events: list[str] = []

        def clear() -> None:
            events.append("clear")

        def origin() -> object:
            events.append("origin")
            return object()

        with (
            redirect_stdout(output),
            patch("ysu_net_watch.ui.sys.stdin.isatty", return_value=True),
            patch("ysu_net_watch.ui._enable_windows_ansi"),
            patch("ysu_net_watch.ui.clear_console", side_effect=clear),
            patch("ysu_net_watch.ui._get_cursor_position", side_effect=origin),
            patch("ysu_net_watch.ui._set_cursor_position", return_value=True),
            patch("msvcrt.getwch", side_effect=["\xe0", "P", "\r"]),
        ):
            selected = select_menu("管理定时器", [f"定时器 {index}" for index in range(1, 12)])

        self.assertEqual(selected, 1)
        self.assertEqual(events, ["clear", "origin"])

    def test_arrow_keys_wrap_and_highlight_all_six_options(self) -> None:
        output = TtyBuffer()
        options = [f"选项 {index}" for index in range(1, 7)]
        with (
            redirect_stdout(output),
            patch("ysu_net_watch.ui.sys.stdin.isatty", return_value=True),
            patch("ysu_net_watch.ui._enable_windows_ansi"),
            patch("ysu_net_watch.ui._get_cursor_position", return_value=object()),
            patch("ysu_net_watch.ui._set_cursor_position", return_value=True) as move,
            patch("msvcrt.getwch", side_effect=["\xe0", "H", "\r"]),
        ):
            selected = select_menu("菜单", options)

        self.assertEqual(selected, 5)
        move.assert_called_once()
        self.assertIn("\x1b[7m> 6. 选项 6\x1b[0m", output.getvalue())

    def test_dynamic_title_refreshes_without_keypress(self) -> None:
        output = TtyBuffer()
        states = iter(["运行状态：等待", "运行状态：认证成功", "运行状态：认证成功"])
        with (
            redirect_stdout(output),
            patch("ysu_net_watch.ui.sys.stdin.isatty", return_value=True),
            patch("ysu_net_watch.ui._enable_windows_ansi"),
            patch("ysu_net_watch.ui._get_cursor_position", return_value=object()),
            patch("ysu_net_watch.ui._set_cursor_position", return_value=True),
            patch("ysu_net_watch.ui.time.sleep"),
            patch("msvcrt.kbhit", side_effect=[False, True]),
            patch("msvcrt.getwch", return_value="\r"),
        ):
            selected = select_menu(lambda: next(states), ["继续"])

        self.assertEqual(selected, 0)
        self.assertIn("运行状态：认证成功", output.getvalue())


if __name__ == "__main__":
    unittest.main()

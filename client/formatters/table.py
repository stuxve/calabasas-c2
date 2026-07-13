"""
Rich table output formatting.
"""

from rich.console import Console
from rich.table import Table as RichTable

from ..protocol.tlv import iter_tlv
from ..protocol.commands import CallbackType
from .transforms import apply_transform


console = Console(stderr=True, no_color=True)


class FormattedOutput:
    def __init__(self, success: bool = True, text: str = "",
                 table: object = None, raw_rows: list = None,
                 file_data: bytes = None, error: str = ""):
        self.success = success
        self.text = text
        self.table = table
        self.raw_rows = raw_rows or []
        self.file_data = file_data
        self.error = error


def render_table(columns: list[str], rows: list[dict], title: str = ""):
    """Render a rich table to console."""
    table = RichTable(title=title, show_lines=False)
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[str(row.get(col, "")) for col in columns])
    console.print(table)


class OutputParser:
    """
    Parse raw task result bytes based on module output format.
    """

    def parse(self, module, raw_result: bytes) -> FormattedOutput:
        if not raw_result:
            return FormattedOutput(success=True, text="(no output)")

        if module.output_format == "table":
            return self._parse_table(module, raw_result)
        elif module.output_format == "raw":
            return self._parse_raw(raw_result)
        elif module.output_format == "file":
            return self._parse_file(raw_result)
        else:
            return self._parse_raw(raw_result)

    def _parse_table(self, module, raw_result: bytes) -> FormattedOutput:
        rows = []
        for entry in iter_tlv(raw_result):
            if entry.type == CallbackType.TABLE_ROW:
                row = {}
                col_idx = 0
                for col_entry in iter_tlv(entry.value):
                    if col_idx < len(module.columns):
                        col_name = module.columns[col_idx]
                        raw_val = col_entry.value.decode("utf-8", errors="replace")
                        if col_name in module.column_transforms:
                            raw_val = apply_transform(
                                module.column_transforms[col_name], raw_val
                            )
                        row[col_name] = raw_val
                    col_idx += 1
                rows.append(row)
            elif entry.type == CallbackType.ERROR:
                return FormattedOutput(
                    success=False,
                    error=entry.value.decode("utf-8", errors="replace"),
                )

        return FormattedOutput(success=True, raw_rows=rows)

    def _parse_raw(self, raw_result: bytes) -> FormattedOutput:
        text_parts = []
        for entry in iter_tlv(raw_result):
            if entry.type in (CallbackType.OUTPUT, CallbackType.OUTPUT_UTF8):
                text_parts.append(entry.value.decode("utf-8", errors="replace"))
            elif entry.type == CallbackType.ERROR:
                return FormattedOutput(
                    success=False,
                    error=entry.value.decode("utf-8", errors="replace"),
                )

        # If no TLV structure, treat entire buffer as raw text
        if not text_parts:
            return FormattedOutput(
                success=True,
                text=raw_result.decode("utf-8", errors="replace"),
            )

        return FormattedOutput(success=True, text="".join(text_parts))

    def _parse_file(self, raw_result: bytes) -> FormattedOutput:
        chunks = []
        for entry in iter_tlv(raw_result):
            if entry.type == CallbackType.FILE_CHUNK:
                chunks.append(entry.value)
        return FormattedOutput(success=True, file_data=b"".join(chunks))

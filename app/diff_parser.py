from typing import List, Dict, Any, Optional
import io

try:
    from unidiff import PatchSet
    HAS_UNIDIFF = True
except ImportError:
    HAS_UNIDIFF = False

class ParsedHunk:
    def __init__(self, target_start: int, lines: List[Dict[str, Any]]):
        self.target_start = target_start
        self.lines = lines  # list of {"type": "+|-| ", "content": str, "line_no": int}

    @property
    def added_lines(self) -> List[tuple]:
        return [(l["line_no"], l["content"]) for l in self.lines if l["type"] == "+"]

    @property
    def raw_added_text(self) -> str:
        return "\n".join(l["content"] for l in self.lines if l["type"] == "+")

class ParsedFileDiff:
    def __init__(self, path: str, is_new: bool = False, is_deleted: bool = False):
        self.path = path
        self.is_new = is_new
        self.is_deleted = is_deleted
        self.hunks: List[ParsedHunk] = []
        self.added_count = 0
        self.deleted_count = 0

def parse_unified_diff(diff_text: str) -> List[ParsedFileDiff]:
    """
    Parses unified diff text into structured objects.
    Uses unidiff if available; falls back to native line-by-line parser.
    """
    if HAS_UNIDIFF:
        try:
            return _parse_with_unidiff(diff_text)
        except Exception:
            pass

    return _parse_with_native_fallback(diff_text)

def _parse_with_unidiff(diff_text: str) -> List[ParsedFileDiff]:
    patch = PatchSet(io.StringIO(diff_text))
    result = []

    for pf in patch:
        target_path = pf.path or pf.target_file or pf.source_file or "unknown"
        # Strip b/ or a/ prefix if present
        if target_path.startswith("b/") or target_path.startswith("a/"):
            target_path = target_path[2:]

        parsed_file = ParsedFileDiff(
            path=target_path,
            is_new=pf.is_added_file,
            is_deleted=pf.is_removed_file
        )

        for h in pf:
            hunk_lines = []
            curr_target_line = h.target_start or 1

            for line in h:
                ltype = line.line_type
                content = line.value.rstrip("\r\n")

                if ltype == "+":
                    hunk_lines.append({"type": "+", "content": content, "line_no": curr_target_line})
                    curr_target_line += 1
                    parsed_file.added_count += 1
                elif ltype == "-":
                    hunk_lines.append({"type": "-", "content": content, "line_no": 0})
                    parsed_file.deleted_count += 1
                else:
                    hunk_lines.append({"type": " ", "content": content, "line_no": curr_target_line})
                    curr_target_line += 1

            parsed_file.hunks.append(ParsedHunk(target_start=h.target_start or 1, lines=hunk_lines))

        result.append(parsed_file)

    return result

def _parse_with_native_fallback(diff_text: str) -> List[ParsedFileDiff]:
    """Lightweight fallback parser when unidiff library is not present."""
    files: List[ParsedFileDiff] = []
    current_file: Optional[ParsedFileDiff] = None
    current_hunk_lines: List[Dict[str, Any]] = []
    target_line = 1

    lines = diff_text.splitlines()

    for line in lines:
        if line.startswith("diff --git"):
            if current_file:
                if current_hunk_lines:
                    current_file.hunks.append(ParsedHunk(target_start=1, lines=current_hunk_lines))
                files.append(current_file)
                current_hunk_lines = []

            parts = line.split()
            path = parts[-1].lstrip("b/") if len(parts) >= 4 else "unknown"
            current_file = ParsedFileDiff(path=path)

        elif line.startswith("+++ "):
            raw_path = line[4:].strip()
            if raw_path.startswith("b/"):
                raw_path = raw_path[2:]
            if current_file and raw_path != "/dev/null":
                current_file.path = raw_path

        elif line.startswith("@@"):
            if current_file and current_hunk_lines:
                current_file.hunks.append(ParsedHunk(target_start=target_line, lines=current_hunk_lines))
                current_hunk_lines = []
            # Extract starting line number if possible
            try:
                plus_part = line.split("+")[1].split()[0]
                target_line = int(plus_part.split(",")[0])
            except Exception:
                target_line = 1

        elif current_file is not None:
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk_lines.append({"type": "+", "content": line[1:], "line_no": target_line})
                current_file.added_count += 1
                target_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk_lines.append({"type": "-", "content": line[1:], "line_no": 0})
                current_file.deleted_count += 1
            elif line.startswith(" "):
                current_hunk_lines.append({"type": " ", "content": line[1:], "line_no": target_line})
                target_line += 1

    if current_file:
        if current_hunk_lines:
            current_file.hunks.append(ParsedHunk(target_start=target_line, lines=current_hunk_lines))
        files.append(current_file)

    return files

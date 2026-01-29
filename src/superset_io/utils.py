import io
import zipfile
from pathlib import Path


def zipfile_buffer_from_folder(folder: Path | str) -> io.BytesIO:
    """Create a zipfile.ZipFile object from a folder path in memory.
    Args:
        folder (Path | str): Path to the folder to be zipped.
    Returns:
        zipfile.ZipFile: In-memory zipfile object.
    """

    folder = Path(folder)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in folder.rglob("*"):
            if path.is_file():
                # Path inside the zip, relative to the folder root
                arcname = path.relative_to(folder)
                zf.write(path, arcname)
    buffer.seek(0)  # Reset buffer pointer to the beginning for reading
    return buffer

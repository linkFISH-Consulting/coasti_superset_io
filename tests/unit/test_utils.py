"""
Unit tests for utility functions.
"""

import io
import zipfile
from importlib import metadata
from pathlib import Path

import pytest

from superset_io.utils import (
    get_version,
    validate_assets_bundle_structure,
    zipfile_buffer_from_folder,
    zipfile_buffer_from_zipfile,
)


class TestZipfileBufferFromFolder:
    """Tests for zipfile_buffer_from_folder function."""

    def test_create_zip_from_folder(self, tmp_path):
        """Test creating a ZIP from a folder structure."""
        # Create a test folder structure
        test_dir = tmp_path / "test_folder"
        test_dir.mkdir()

        # Create some files
        (test_dir / "file1.txt").write_text("Content 1")
        (test_dir / "file2.txt").write_text("Content 2")
        subdir = test_dir / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("Content 3")

        # Create ZIP
        zip_buffer = zipfile_buffer_from_folder(test_dir)

        # Verify the ZIP
        assert isinstance(zip_buffer, io.BytesIO)

        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert "test_folder/file1.txt" in zf.namelist()
            assert "test_folder/file2.txt" in zf.namelist()
            assert "test_folder/subdir/file3.txt" in zf.namelist()

            # Verify file contents
            assert zf.read("test_folder/file1.txt").decode() == "Content 1"
            assert zf.read("test_folder/file2.txt").decode() == "Content 2"
            assert zf.read("test_folder/subdir/file3.txt").decode() == "Content 3"

    def test_nonexistent_folder(self):
        """Test that non-existent folder raises ValueError."""
        with pytest.raises(ValueError, match="Not a folder"):
            zipfile_buffer_from_folder("/nonexistent/path")

    def test_file_instead_of_folder(self, tmp_path):
        """Test that passing a file instead of folder raises ValueError."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        with pytest.raises(ValueError, match="Not a folder"):
            zipfile_buffer_from_folder(test_file)


class TestZipfileBufferFromZipfile:
    """Tests for zipfile_buffer_from_zipfile function."""

    def test_copy_existing_zip(self, tmp_path):
        """Test copying an existing ZIP file to a buffer."""
        # Create a test ZIP file
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "Content 1")
            zf.writestr("subdir/file2.txt", "Content 2")

        # Copy to buffer
        zip_buffer = zipfile_buffer_from_zipfile(zip_path)

        # Verify the buffer
        assert isinstance(zip_buffer, io.BytesIO)

        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert "file1.txt" in zf.namelist()
            assert "subdir/file2.txt" in zf.namelist()
            assert zf.read("file1.txt").decode() == "Content 1"

    def test_nonexistent_zip(self):
        """Test that non-existent ZIP file raises error on read."""
        # The function will try to open the file, which will raise FileNotFoundError
        # when the file is read. The function doesn't check existence beforehand.
        non_existent = Path("/nonexistent/path.zip")

        # This will raise FileNotFoundError when trying to open the file
        with pytest.raises(FileNotFoundError):
            zipfile_buffer_from_zipfile(non_existent)


class TestValidateAssetsBundleStructure:
    """Tests for validate_assets_bundle_structure function."""

    def test_valid_structure(self):
        """Test validation of a valid Superset assets bundle."""
        # Create a valid ZIP structure
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("assets_export_20240101/metadata.yaml", "version: 1.0")
            zf.writestr("assets_export_20240101/dashboards/test.yaml", "title: Test")
            zf.writestr("assets_export_20240101/charts/", "")  # Empty directory
            zf.writestr("assets_export_20240101/datasets/", "")

        zip_buffer.seek(0)

        # Should not raise any exception
        validate_assets_bundle_structure(zip_buffer)

    def test_valid_structure_with_bytes(self):
        """Test validation with bytes input."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("assets_export_20240101/metadata.yaml", "version: 1.0")
            zf.writestr("assets_export_20240101/dashboards/test.yaml", "title: Test")

        zip_bytes = zip_buffer.getvalue()

        # Should not raise any exception
        validate_assets_bundle_structure(zip_bytes)

    def test_valid_structure_with_path(self, tmp_path):
        """Test validation with Path input."""
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("assets_export_20240101/metadata.yaml", "version: 1.0")
            zf.writestr("assets_export_20240101/dashboards/test.yaml", "title: Test")

        # Should not raise any exception
        validate_assets_bundle_structure(zip_path)

    def test_missing_metadata(self):
        """Test validation fails when metadata.yaml is missing."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("assets_export_20240101/dashboards/test.yaml", "title: Test")

        zip_buffer.seek(0)

        with pytest.raises(ValueError, match="Missing metadata.yaml"):
            validate_assets_bundle_structure(zip_buffer)

    def test_metadata_not_in_root_folder(self):
        """Test validation fails when metadata.yaml is not in root folder."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("metadata.yaml", "version: 1.0")  # Not in root folder
            zf.writestr("dashboards/test.yaml", "title: Test")
            zf.writestr("charts/test.yaml", "title: Test")

        zip_buffer.seek(0)

        with pytest.raises(ValueError, match="Expected exactly one top-level folder"):
            validate_assets_bundle_structure(zip_buffer)

    def test_multiple_root_folders(self):
        """Test validation fails with multiple top-level folders."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("folder1/metadata.yaml", "version: 1.0")
            zf.writestr("folder2/dashboards/test.yaml", "title: Test")

        zip_buffer.seek(0)

        with pytest.raises(ValueError, match="Expected exactly one top-level folder"):
            validate_assets_bundle_structure(zip_buffer)

    def test_metadata_in_wrong_location(self):
        """Test validation fails when metadata.yaml is not at expected path."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Also add another metadata in wrong place (should still pass)
            zf.writestr("assets_export_20240101/another/metadata.yaml", "version: 1.0")

        zip_buffer.seek(0)

        # This should still pass because we have metadata at the expected path
        with pytest.raises(
            ValueError, match="metadata.yaml not found at expected path"
        ):
            validate_assets_bundle_structure(zip_buffer)

    def test_empty_zip(self):
        """Test validation fails with empty ZIP."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED):
            pass  # Empty zip

        zip_buffer.seek(0)

        with pytest.raises(ValueError, match="Missing metadata.yaml"):
            validate_assets_bundle_structure(zip_buffer)


class TestGetVersion:
    def test_get_version_returns_version_string(self, monkeypatch):
        monkeypatch.setattr(metadata, "version", lambda name: "1.2.3")

        assert get_version() == "1.2.3"

    def test_get_version_returns_fallback_when_package_not_found(self, monkeypatch):
        def _raise(_name):
            raise metadata.PackageNotFoundError

        monkeypatch.setattr(metadata, "version", _raise)

        assert get_version() == "[not found] Use `uv sync` when developing!"

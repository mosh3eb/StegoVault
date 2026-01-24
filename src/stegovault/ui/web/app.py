"""
StegoVault Web Interface (Flask)
Provides a beginner-friendly UI for embed/extract/detect/capacity/privacy.
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, jsonify, render_template, request, send_file, abort
from werkzeug.utils import secure_filename
from PIL import Image

# Import engine (support both folder casings)
try:
    from StegoVault.core import StegoEngine
except Exception:  # pragma: no cover
    from stegovault.core import StegoEngine  # type: ignore


APP_NAME = "StegoVault"
APP_VERSION = "1.00"
BRAND_BG = "#090B29"

if hasattr(sys, "_MEIPASS"):
    ROOT = Path(sys._MEIPASS)
else:
    ROOT = Path(__file__).resolve().parent.parent

WEB_ROOT = ROOT / "web"
DATA_DIR = WEB_ROOT / "_data"
UPLOADS_DIR = DATA_DIR / "uploads"
OUTPUTS_DIR = DATA_DIR / "outputs"

for d in (DATA_DIR, UPLOADS_DIR, OUTPUTS_DIR):
    d.mkdir(parents=True, exist_ok=True)


@dataclass
class StoredFile:
    path: Path
    download_name: str


downloads: Dict[str, StoredFile] = {}


def _new_token() -> str:
    return uuid.uuid4().hex


def _save_upload(file_storage, subdir: Path) -> Path:
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise ValueError("Missing filename")
    token = _new_token()
    out = subdir / f"{token}_{filename}"
    file_storage.save(out)
    return out


def _bool(v: Optional[str]) -> bool:
    return str(v).lower() in ("1", "true", "yes", "on")


def _cleanup_old(max_files: int = 200) -> None:
    """Basic cleanup to avoid unbounded growth on demo servers."""
    try:
        files = sorted(OUTPUTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files[max_files:]:
            p.unlink(missing_ok=True)
    except Exception:
        pass


app = Flask(
    __name__,
    template_folder=str(WEB_ROOT / "templates"),
    static_folder=str(WEB_ROOT / "static"),
)

# Initialize metadata storage for embedding settings
app.embed_metadata = {}

# Add CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Increase max upload size (default is 16MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB


@app.get("/")
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        brand_bg=BRAND_BG,
        logo_path="/static/logo.png",
    )


@app.get("/download/<token>")
def download(token: str):
    item = downloads.get(token)
    if not item or not item.path.exists():
        abort(404)
    
    # Ensure PNG files are served with correct content type
    mimetype = None
    if item.path.suffix.lower() == '.png':
        mimetype = 'image/png'
    
    return send_file(
        item.path, 
        as_attachment=True, 
        download_name=item.download_name,
        mimetype=mimetype
    )


@app.post("/api/embed")
def api_embed():
    try:
        if "payload" not in request.files:
            return jsonify({"ok": False, "error": "Missing file to embed (payload)."}), 400

        payload_file = request.files["payload"]
        if not payload_file.filename:
            return jsonify({"ok": False, "error": "No file selected."}), 400

        payload_path = _save_upload(payload_file, UPLOADS_DIR)
        cover_path: Optional[Path] = None
        if "cover" in request.files and request.files["cover"].filename:
            cover_path = _save_upload(request.files["cover"], UPLOADS_DIR)

        password = request.form.get("password") or None
        mode = request.form.get("mode", "pixel")
        compress = _bool(request.form.get("compress"))
        robustness = _bool(request.form.get("robustness"))
        anti = _bool(request.form.get("anti_steganalysis"))
        strip_metadata = _bool(request.form.get("strip_metadata"))
        quality = int(request.form.get("quality", 95))
        quality = max(1, min(100, quality))  # Clamp between 1-100

        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)

        out_name = f"{Path(payload_path.name).stem}_stego.png"
        out_path = OUTPUTS_DIR / f"{_new_token()}_{out_name}"

        ok = engine.embed_file(
            input_file=str(payload_path),
            cover_image=str(cover_path) if cover_path else None,
            output_image=str(out_path),
            password=password,
            mode=mode,
            compress=compress,
            quality=quality,
            show_progress=False,
            strip_metadata=strip_metadata,
            enable_robustness=robustness,
            enable_anti_steganalysis=anti,
        )
        if not ok:
            err = getattr(engine, "_last_error", None) or "Embedding failed."
            return jsonify({"ok": False, "error": err}), 400

        # Verify the output file exists and is valid
        if not out_path.exists():
            return jsonify({"ok": False, "error": "Embedding completed but output file not found."}), 500
        
        # Verify the output file is a valid PNG and test extraction
        verification_passed = False
        try:
            test_img = Image.open(str(out_path))
            if test_img.format != 'PNG':
                return jsonify({"ok": False, "error": "Output file is not a valid PNG."}), 500
            test_img.verify()
            test_img = Image.open(str(out_path))  # Reopen after verify
            
            # Test extraction to verify the file is valid
            # Use the SAME settings as embedding for extraction test
            print(f"✓ Output file verified: {out_path.stat().st_size} bytes, format: PNG")
            print(f"Testing extraction from embedded file...")
            print(f"  Settings: robustness={robustness}, mode={mode}, compressed={compress}, encrypted={password is not None}")
            test_engine = StegoEngine(enable_robustness=robustness, enable_anti_steganalysis=anti)
            test_extract = test_engine.extract_file(
                stego_image=str(out_path),
                output_path=str(OUTPUTS_DIR / "verification_test"),
                password=password,
                verify=True,
            )
            if test_extract:
                # Clean up test file
                Path(test_extract).unlink(missing_ok=True)
                verification_passed = True
                print(f"✓ Verification: File can be extracted successfully on server")
            else:
                error_msg = getattr(test_engine, '_last_error', 'Unknown error')
                print(f"⚠ Warning: File created but extraction test failed: {error_msg}")
                print(f"  This might indicate an issue with the embedding process.")
        except Exception as verify_err:
            import traceback
            print(f"Warning: Could not verify output file: {verify_err}")
            print(f"Traceback: {traceback.format_exc()}")
            # Don't fail, just log the warning

        token = _new_token()
        downloads[token] = StoredFile(path=out_path, download_name=out_name)
        
        # Also create a token for direct extraction (server-side file)
        # Store embedding settings with the file for proper extraction
        extract_token = _new_token()
        downloads[extract_token] = StoredFile(path=out_path, download_name=out_name)
        
        # Store metadata about how the file was embedded
        embed_metadata = {
            "robustness": robustness,
            "anti_steganalysis": anti,
            "mode": mode,
            "compressed": compress,
            "encrypted": password is not None
        }
        app.embed_metadata[extract_token] = embed_metadata
        print(f"Stored embed metadata for token {extract_token}: {embed_metadata}")
        
        _cleanup_old()

        response_data = {
            "ok": True,
            "download_url": f"/download/{token}",
            "extract_token": extract_token,  # For direct extraction without download
            "auto_actions": getattr(engine, "_auto_actions", []),
            "file_info": {
                "size": out_path.stat().st_size,
                "format": "PNG"
            },
            "verified": verification_passed,
            "embed_settings": embed_metadata,
            "note": "Tip: Use 'Extract from Server' button to test extraction without downloading."
        }
        
        if verification_passed:
            response_data["message"] = "File embedded and verified - extraction test passed!"
        else:
            response_data["warning"] = "File embedded but extraction test failed. The file may still work when downloaded."
        
        return jsonify(response_data)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Embed error: {error_details}")  # Log to server console
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/extract")
def api_extract():
    try:
        if "stego" not in request.files:
            return jsonify({"ok": False, "error": "Missing stego image."}), 400

        stego_file = request.files["stego"]
        if not stego_file.filename:
            return jsonify({"ok": False, "error": "No file selected."}), 400

        stego_path = _save_upload(stego_file, UPLOADS_DIR)
        password = request.form.get("password") or None

        # Verify the file is a PNG and check its integrity
        try:
            img = Image.open(stego_path)
            if img.format != 'PNG':
                return jsonify({
                    "ok": False, 
                    "error": f"Invalid image format: {img.format}. Only PNG images are supported for extraction."
                }), 400
            
            # Verify image can be loaded and has valid dimensions
            img.verify()
            img = Image.open(stego_path)  # Reopen after verify
            if img.size[0] == 0 or img.size[1] == 0:
                return jsonify({"ok": False, "error": "Invalid image dimensions."}), 400
            
            # Check file size
            file_size = stego_path.stat().st_size
            if file_size < 100:  # PNG header is at least this size
                return jsonify({"ok": False, "error": "File is too small to be a valid PNG."}), 400
            
            print(f"Extracting from: {stego_path}, size: {file_size} bytes, dimensions: {img.size}")
            
            # Check PNG signature
            with open(stego_path, 'rb') as f:
                png_header = f.read(8)
                print(f"PNG header: {png_header.hex()}")
                if not png_header.startswith(b'\x89PNG\r\n\x1a\n'):
                    return jsonify({
                        "ok": False, 
                        "error": "File does not have a valid PNG header. It may have been corrupted or converted."
                    }), 400
        except Exception as e:
            import traceback
            print(f"Image validation error: {traceback.format_exc()}")
            return jsonify({"ok": False, "error": f"Invalid image file: {str(e)}"}), 400

        # Try extraction - first with robustness enabled, then without
        # Anti-steganalysis shouldn't affect extraction, but we'll try both ways
        extracted_path = None
        last_error = None
        
        # Try with robustness first (for recovery)
        for attempt in [("robustness=True", True, False), ("robustness=False", False, False), ("with anti-steganalysis", True, True)]:
            attempt_name, use_robustness, use_anti = attempt
            print(f"Extraction attempt {attempt_name}: robustness={use_robustness}, anti={use_anti}, password={'Yes' if password else 'No'}")
            
            try:
                engine = StegoEngine(enable_robustness=use_robustness, enable_anti_steganalysis=use_anti)
                extracted_path = engine.extract_file(
                    stego_image=str(stego_path),
                    output_path=str(OUTPUTS_DIR) + os.sep,
                    password=password,
                    verify=True,
                )
                if extracted_path:
                    print(f"✓ Extraction successful with {attempt_name}")
                    break
                else:
                    last_error = getattr(engine, "_last_error", None) or "Extraction failed"
                    print(f"✗ Extraction failed with {attempt_name}: {last_error}")
            except Exception as extract_err:
                import traceback
                error_trace = traceback.format_exc()
                last_error = str(extract_err)
                print(f"✗ Extraction exception with {attempt_name}: {last_error}")
                print(f"Traceback: {error_trace}")
                continue
        
        if not extracted_path:
            err = last_error or "Extraction failed after all attempts."
            
            # Provide more helpful error messages
            if "Not a valid stego image" in err:
                err = (
                    "Not a valid stego image. Possible reasons:\n"
                    "• The image was not created with StegoVault\n"
                    "• The image was corrupted or modified\n"
                    "• Wrong password (if encrypted)\n"
                    "• Image format was converted (must be PNG)\n"
                    "• Anti-steganalysis protection may have affected extraction\n"
                    "  Try embedding without anti-steganalysis for better compatibility"
                )
            elif "password" in err.lower() or "incorrect" in err.lower():
                err = "Incorrect password. Please check and try again."
            
            return jsonify({"ok": False, "error": err}), 400

        extracted_path = Path(extracted_path)
        if not extracted_path.exists():
            return jsonify({"ok": False, "error": "Extraction completed but output file not found."}), 500

        token = _new_token()
        downloads[token] = StoredFile(path=extracted_path, download_name=extracted_path.name)
        _cleanup_old()
        return jsonify({"ok": True, "download_url": f"/download/{token}"})
    except ValueError as e:
        # Handle validation errors
        error_msg = str(e)
        if "Not a valid stego image" in error_msg:
            error_msg = (
                "Not a valid stego image. Possible reasons:\n"
                "• The image was not created with StegoVault\n"
                "• The image was corrupted or modified\n"
                "• Wrong password (if encrypted)\n"
                "• Image format was converted (must be PNG)"
            )
        return jsonify({"ok": False, "error": error_msg}), 400
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Extract error: {error_details}")  # Log to server console
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/extract-direct")
def api_extract_direct():
    """Extract directly from a server-side file (by token from embed)"""
    try:
        extract_token = request.form.get("token")
        if not extract_token:
            return jsonify({"ok": False, "error": "Missing extraction token."}), 400
        
        item = downloads.get(extract_token)
        if not item or not item.path.exists():
            return jsonify({"ok": False, "error": "Invalid or expired token."}), 400
        
        password = request.form.get("password") or None
        
        # Get embedding settings if available
        embed_settings = getattr(app, 'embed_metadata', {}).get(extract_token, {})
        robustness = embed_settings.get("robustness", True)  # Default to True for recovery
        anti = embed_settings.get("anti_steganalysis", False)
        
        print(f"Direct extraction: token={extract_token}, robustness={robustness}, anti={anti}, has_password={password is not None}")
        
        engine = StegoEngine(enable_robustness=robustness, enable_anti_steganalysis=anti)
        
        extracted_path = engine.extract_file(
            stego_image=str(item.path),
            output_path=str(OUTPUTS_DIR) + os.sep,
            password=password,
            verify=True,
        )
        
        if not extracted_path:
            err = getattr(engine, "_last_error", None) or "Extraction failed."
            return jsonify({"ok": False, "error": err}), 400
        
        extracted_path = Path(extracted_path)
        if not extracted_path.exists():
            return jsonify({"ok": False, "error": "Extraction completed but output file not found."}), 500
        
        token = _new_token()
        downloads[token] = StoredFile(path=extracted_path, download_name=extracted_path.name)
        _cleanup_old()
        return jsonify({"ok": True, "download_url": f"/download/{token}"})
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Direct extract error: {error_details}")
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/detect")
def api_detect():
    try:
        if "image" not in request.files:
            return jsonify({"ok": False, "error": "Missing image."}), 400
        image_path = _save_upload(request.files["image"], UPLOADS_DIR)
        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)
        result = engine.detect_steganography(str(image_path))
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/capacity")
def api_capacity():
    try:
        if "image" not in request.files:
            return jsonify({"ok": False, "error": "Missing image."}), 400
        image_path = _save_upload(request.files["image"], UPLOADS_DIR)
        mode = request.form.get("mode", "lsb")
        compress = _bool(request.form.get("compress", False))
        
        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)
        cap = engine.get_capacity_info(cover_image=str(image_path), mode=mode)
        
        # If a file is provided, check if it fits
        fit_analysis = None
        if "file" in request.files and request.files["file"].filename:
            file_path = _save_upload(request.files["file"], UPLOADS_DIR)
            fit_analysis = engine.check_file_fits(
                file_path=str(file_path),
                cover_image=str(image_path),
                mode=mode,
                compress=compress
            )
            cap["fit_analysis"] = fit_analysis
        
        return jsonify({"ok": True, "result": cap})
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Capacity error: {error_details}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/privacy")
def api_privacy():
    try:
        if "image" not in request.files:
            return jsonify({"ok": False, "error": "Missing image."}), 400
        image_path = _save_upload(request.files["image"], UPLOADS_DIR)
        strip = _bool(request.form.get("strip"))
        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)
        report = engine.get_privacy_report(str(image_path))

        cleaned_download_url = None
        if strip:
            out_name = f"{image_path.stem}_clean{image_path.suffix}"
            out_path = OUTPUTS_DIR / f"{_new_token()}_{out_name}"
            cleaned = engine.strip_metadata(str(image_path), str(out_path))
            cleaned_path = Path(cleaned)
            token = _new_token()
            downloads[token] = StoredFile(path=cleaned_path, download_name=out_name)
            cleaned_download_url = f"/download/{token}"

        _cleanup_old()
        return jsonify({"ok": True, "result": report, "cleaned_download_url": cleaned_download_url})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/embed-archive")
def api_embed_archive():
    """Embed multiple files/folders as an archive"""
    try:
        if "files" not in request.files:
            return jsonify({"ok": False, "error": "Missing files to embed."}), 400
        
        files = request.files.getlist("files")
        if not files or not any(f.filename for f in files):
            return jsonify({"ok": False, "error": "No files selected."}), 400

        # Save all uploaded files
        file_paths = []
        for file in files:
            if file.filename:
                file_path = _save_upload(file, UPLOADS_DIR)
                file_paths.append(str(file_path))

        cover_path: Optional[Path] = None
        if "cover" in request.files and request.files["cover"].filename:
            cover_path = _save_upload(request.files["cover"], UPLOADS_DIR)

        password = request.form.get("password") or None
        mode = request.form.get("mode", "pixel")
        compress = _bool(request.form.get("compress"))
        robustness = _bool(request.form.get("robustness"))
        anti = _bool(request.form.get("anti_steganalysis"))
        strip_metadata = _bool(request.form.get("strip_metadata"))
        quality = int(request.form.get("quality", 95))
        quality = max(1, min(100, quality))

        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)

        out_name = "archive_stego.png"
        out_path = OUTPUTS_DIR / f"{_new_token()}_{out_name}"

        ok = engine.embed_archive(
            file_paths=file_paths,
            cover_image=str(cover_path) if cover_path else None,
            output_image=str(out_path),
            password=password,
            mode=mode,
            compress=compress,
            quality=quality,
            strip_metadata=strip_metadata,
            enable_robustness=robustness,
            enable_anti_steganalysis=anti,
        )
        if not ok:
            err = getattr(engine, "_last_error", None) or "Archive embedding failed."
            return jsonify({"ok": False, "error": err}), 400

        token = _new_token()
        downloads[token] = StoredFile(path=out_path, download_name=out_name)
        extract_token = _new_token()
        downloads[extract_token] = StoredFile(path=out_path, download_name=out_name)
        
        embed_metadata = {
            "robustness": robustness,
            "anti_steganalysis": anti,
            "mode": mode,
            "compressed": compress,
            "encrypted": password is not None,
            "is_archive": True
        }
        app.embed_metadata[extract_token] = embed_metadata
        
        _cleanup_old()
        return jsonify({
            "ok": True,
            "download_url": f"/download/{token}",
            "extract_token": extract_token,
            "auto_actions": getattr(engine, "_auto_actions", []),
            "file_info": {
                "size": out_path.stat().st_size,
                "format": "PNG"
            }
        })
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Embed archive error: {error_details}")
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/extract-archive")
def api_extract_archive():
    """Extract archive from stego image"""
    try:
        if "stego" not in request.files:
            return jsonify({"ok": False, "error": "Missing stego image."}), 400

        stego_file = request.files["stego"]
        if not stego_file.filename:
            return jsonify({"ok": False, "error": "No file selected."}), 400

        stego_path = _save_upload(stego_file, UPLOADS_DIR)
        password = request.form.get("password") or None
        robustness = _bool(request.form.get("robustness", True))

        engine = StegoEngine(enable_robustness=robustness, enable_anti_steganalysis=False)

        # Create output directory for archive
        archive_output_dir = OUTPUTS_DIR / f"archive_{_new_token()}"
        archive_output_dir.mkdir(parents=True, exist_ok=True)

        result = engine.extract_archive(
            stego_image=str(stego_path),
            output_dir=str(archive_output_dir),
            password=password,
            enable_robustness=robustness,
        )

        if not result:
            err = getattr(engine, "_last_error", None) or "Archive extraction failed."
            return jsonify({"ok": False, "error": err}), 400

        # Create a zip file of the extracted archive
        import zipfile
        zip_path = OUTPUTS_DIR / f"{_new_token()}_extracted_archive.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(archive_output_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(archive_output_dir)
                    zipf.write(file_path, arcname)

        token = _new_token()
        downloads[token] = StoredFile(path=zip_path, download_name="extracted_archive.zip")
        _cleanup_old()
        
        return jsonify({
            "ok": True,
            "download_url": f"/download/{token}",
            "file_count": result.get("file_count", 0),
            "total_size": result.get("total_size", 0),
            "auto_actions": getattr(engine, "_auto_actions", [])
        })
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Extract archive error: {error_details}")
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/info")
def api_info():
    """Get metadata from stego image without extracting"""
    try:
        if "image" not in request.files:
            return jsonify({"ok": False, "error": "Missing image."}), 400
        
        image_path = _save_upload(request.files["image"], UPLOADS_DIR)
        password = request.form.get("password") or None
        
        engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)
        metadata = engine.get_metadata(str(image_path), password)
        
        if not metadata:
            return jsonify({
                "ok": False,
                "error": "No steganography metadata found. This image may not contain hidden data, or the password is incorrect."
            }), 400
        
        return jsonify({"ok": True, "metadata": metadata})
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Info error: {error_details}")
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500


@app.post("/api/reset-demo")
def api_reset_demo():
    """Optional: wipe web demo files (useful in shared demos)."""
    try:
        if DATA_DIR.exists():
            shutil.rmtree(DATA_DIR)
        for d in (DATA_DIR, UPLOADS_DIR, OUTPUTS_DIR):
            d.mkdir(parents=True, exist_ok=True)
        downloads.clear()
        app.embed_metadata.clear()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



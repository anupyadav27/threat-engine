import os
import sys
import json
import zipfile
import signal
from scanner_plugin import detect_language, get_scanner

# Timeout handler
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Scan timeout")

def scan_path(input_path):
    results = []
    errors = []
    engine_used = None

    def scan_single_file(file_path):
        lang = detect_language(file_path)
        if not lang:
            errors.append({"file": file_path, "error": "Could not detect language"})
            return None, None
        try:
            # Set timeout for individual file scan (30 seconds max per file)
            if hasattr(signal, 'SIGALRM'):  # Unix/Linux only
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(30)
            
            scanner = get_scanner(lang)
            findings = scanner(file_path)
            
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(0)  # Cancel timeout
            
            return lang, findings
        except TimeoutException:
            errors.append({"file": file_path, "error": "Scan timeout after 30 seconds"})
            return lang, None
        except Exception as e:
            errors.append({"file": file_path, "error": str(e)})
            return lang, None
        finally:
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(0)  # Ensure timeout is cancelled

    if not os.path.exists(input_path):
        errors.append({"error": f"Input path does not exist: {input_path}"})
        return {"engine": None, "input": input_path, "results": results, "errors": errors}

    if os.path.isdir(input_path):
        scan_targets = []
        for root, dirs, files in os.walk(input_path):
            for fname in files:
                if fname.endswith(('.py', '.tf', '.java', '.cs', '.js', '.mjs', '.jsx', '.yml', '.yaml', '.json', '.dockerfile', '.c', '.h', '.cpp', '.cxx', '.cc', '.hpp', '.hxx', '.hh', '.go', '.rb')) or \
                   fname.lower() == 'dockerfile' or fname.lower().startswith('dockerfile.'):
                    scan_targets.append(os.path.join(root, fname))
        for file in scan_targets:
            lang, findings = scan_single_file(file)
            if lang and findings is not None:
                results.append({"file": file, "language": lang, "findings": findings})
        engine_used = "multi (folder)"
    elif os.path.isfile(input_path):
        # Check if it's a supported file type by trying to detect language
        if detect_language(input_path):
            lang, findings = scan_single_file(input_path)
            if lang and findings is not None:
                results.append({"file": input_path, "language": lang, "findings": findings})
            engine_used = lang
        else:
            errors.append({"error": f"Unsupported file type: {input_path}"})
    else:
        errors.append({"error": f"Unsupported input type: {input_path}"})

    return {
        "engine": engine_used,
        "input": input_path,
        "results": results,
        "errors": errors
    }

# CLI usage
if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else input("Enter file or folder path to scan: ").strip()
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, os.path.splitext(os.path.basename(input_path))[0] + "_scan_results.json")
    result = scan_path(input_path)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Scan complete. Results saved to {output_file}")

# FastAPI endpoint for API usage
try:
    from fastapi import FastAPI, UploadFile, File
    import tempfile
    app = FastAPI()

    @app.post("/scan-local")
    async def scan_local_api(file: UploadFile = File(...)):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, file.filename)
            with open(file_path, "wb") as f:
                f.write(await file.read())
            result = scan_path(file_path)
            return result
except ImportError:
    pass

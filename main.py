import os
import io
import time
import math
import hashlib
import base64
import joblib
import pefile
import pandas as pd
import shap
import matplotlib.pyplot as plt
from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import warnings
warnings.filterwarnings('ignore')

# Initialize FastAPI
app = FastAPI(title="SentinAI Backend")

# Load Models
MODEL_PATH = 'malware_detector.pkl'
FEATURES_PATH = 'model_features.pkl'

model = joblib.load(MODEL_PATH)
features_list = joblib.load(FEATURES_PATH)
explainer = shap.TreeExplainer(model)

def get_file_hashes(file_bytes):
    return {
        "MD5": hashlib.md5(file_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(file_bytes).hexdigest()
    }

def extract_pe_metadata(pe):
    try:
        return {
            'Machine': hex(pe.FILE_HEADER.Machine),
            'Entry Point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'Sections': pe.FILE_HEADER.NumberOfSections,
            'Timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp))
        }
    except:
        return {}

def get_section_details(pe):
    sections = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        sections.append({
            "name": name,
            "entropy": round(section.get_entropy(), 4),
            "size": section.Misc_VirtualSize
        })
    return sections

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        file_size_kb = len(file_bytes) / 1024

        try:
            pe = pefile.PE(data=file_bytes)
        except pefile.PEFormatError:
            return JSONResponse(status_code=400, content={"error": "Invalid format. Not a Windows PE (Executable)."})

        # Extract features
        extracted_data = {}
        for feat in features_list:
            val = 0
            if hasattr(pe.OPTIONAL_HEADER, feat): val = getattr(pe.OPTIONAL_HEADER, feat)
            elif hasattr(pe.FILE_HEADER, feat): val = getattr(pe.FILE_HEADER, feat)
            elif hasattr(pe.DOS_HEADER, feat): val = getattr(pe.DOS_HEADER, feat)
            extracted_data[feat] = val

        df_input = pd.DataFrame([extracted_data])[features_list]
        
        # Inference
        probs = model.predict_proba(df_input)[0]
        malware_prob = probs[0]
        safe_prob = probs[1]
        
        # Adjustable Threshold (Fixes Gemini.exe false positive)
        # Require 75% confidence to flag as malware
        is_malware = malware_prob > 0.75
        confidence = max(malware_prob, safe_prob) * 100
        verdict_text = "Malware" if is_malware else "Safe"
        target_idx = 0 if is_malware else 1

        # SHAP Explanation
        plt.style.use('dark_background')
        shap_explanation = explainer(df_input)
        exp_single = shap.Explanation(
            values=shap_explanation.values[0, :, target_idx],
            base_values=shap_explanation.base_values[0, target_idx],
            data=df_input.iloc[0].values,
            feature_names=features_list
        )
        
        fig, ax = plt.subplots(figsize=(8, 4))
        fig.patch.set_facecolor('#0a0a0a')
        ax.set_facecolor('#0a0a0a')
        shap.waterfall_plot(exp_single, max_display=8, show=False)
        plt.tight_layout()
        
        for text in ax.texts: text.set_color('#ffffff')
        
        # Convert plot to Base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        buf.seek(0)
        shap_b64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close(fig)

        return {
            "verdict": verdict_text,
            "confidence": round(confidence, 1),
            "filename": file.filename,
            "size_kb": round(file_size_kb, 1),
            "hashes": get_file_hashes(file_bytes),
            "metadata": extract_pe_metadata(pe),
            "sections": get_section_details(pe),
            "shap_image": f"data:image/png;base64,{shap_b64}"
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# Mount frontend
os.makedirs("static", exist_ok=True)
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

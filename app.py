import streamlit as st
import pandas as pd
import pefile
import joblib
import time
import hashlib
import math
import altair as alt
import os
import shap
import matplotlib.pyplot as plt

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="SentinAI | Explainable Threat Analysis",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- NEON CYBERPUNK CSS & TYPOGRAPHY ---
st.markdown("""
<style>
    :root {
        --glass-bg: rgba(255, 255, 255, 0.04);
        --glass-border: rgba(255, 255, 255, 0.1);
        --glass-hover: rgba(255, 255, 255, 0.08);
        --accent-primary: #007aff;
        --accent-secondary: #5ac8fa;
        --danger: #ff3b30;
        --danger-bg: rgba(255, 59, 48, 0.15);
        --success: #34c759;
        --success-bg: rgba(52, 199, 89, 0.15);
        --text-primary: #f5f5f7;
        --text-secondary: #86868b;
        --bg-gradient: radial-gradient(circle at top right, #1f2129, #000000 70%);
    }

    * {
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        -webkit-font-smoothing: antialiased;
    }
    
    h1, h2, h3, .brand-title {
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
        font-weight: 600;
        letter-spacing: -0.015em;
    }
    
    code, pre, .technical-text {
        font-family: "SF Mono", "Menlo", "Monaco", "Consolas", monospace !important;
    }

    .stApp {
        background: var(--bg-gradient);
        color: var(--text-primary);
    }
    
    /* Hide Streamlit Default UI */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Liquid Glass Panels (Apple VisionOS / macOS style) */
    .glass-panel {
        background: var(--glass-bg);
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border: 1px solid var(--glass-border);
        border-radius: 20px;
        padding: 1.5rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
        margin-bottom: 1.5rem;
        transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
    }
    
    .glass-panel:hover {
        background: var(--glass-hover);
        border-color: rgba(255, 255, 255, 0.15);
        box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.3);
        transform: translateY(-2px);
    }

    /* Custom Headers */
    .brand-title {
        font-size: 3rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        background: linear-gradient(135deg, #fff, #86868b);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }

    .section-title {
        font-size: 1.2rem;
        font-weight: 600;
        color: var(--text-primary);
        letter-spacing: 0.02em;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--glass-border);
    }

    /* Metrics Styling */
    [data-testid="stMetric"] {
        background: var(--glass-bg);
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border: 1px solid var(--glass-border);
        padding: 1rem 1.2rem;
        border-radius: 16px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
    }
    [data-testid="stMetricLabel"] {
        color: var(--text-secondary) !important;
        font-weight: 500;
        font-size: 0.85rem;
        letter-spacing: 0.02em;
        text-transform: uppercase;
    }
    [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        font-size: 1.8rem !important;
    }

    /* Verdict Badges */
    .verdict-malicious {
        background: var(--danger-bg);
        border: 1px solid rgba(255, 59, 48, 0.3);
    }
    .verdict-benign {
        background: var(--success-bg);
        border: 1px solid rgba(52, 199, 89, 0.3);
    }

    .status-badge {
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        letter-spacing: 0.02em;
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        backdrop-filter: blur(10px);
    }

    /* File Uploader */
    .stFileUploader > div {
        background: var(--glass-bg);
        border: 1px dashed rgba(255, 255, 255, 0.3);
        border-radius: 20px;
        padding: 2rem;
        transition: all 0.3s ease;
        backdrop-filter: blur(10px);
    }
    .stFileUploader > div:hover {
        background: var(--glass-hover);
        border-color: rgba(255, 255, 255, 0.5);
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 1.5rem;
        background: transparent;
        border-bottom: 1px solid var(--glass-border);
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        color: var(--text-secondary);
        font-weight: 500;
        font-size: 0.95rem;
        border: none;
        padding: 0 0.5rem;
    }
    .stTabs [aria-selected="true"] {
        color: var(--text-primary);
        background: transparent;
        border-bottom: 2px solid var(--text-primary);
    }
    
    /* DataFrame Styling */
    [data-testid="stDataFrame"] {
        border-radius: 12px;
        border: 1px solid var(--glass-border);
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# --- CORE UTILITY FUNCTIONS ---

@st.cache_resource
def load_ml_assets():
    """Loads the pre-trained Random Forest model and Explainer."""
    try:
        model = joblib.load('malware_detector.pkl')
        features_list = joblib.load('model_features.pkl')
        explainer = shap.TreeExplainer(model)
        return model, features_list, explainer
    except Exception as e:
        st.error(f"Failed to load AI models: {e}. Please ensure 'malware_detector.pkl' and 'model_features.pkl' exist.")
        return None, None, None

def get_file_hashes(file_bytes):
    """Generates cryptographic hashes for file identification."""
    return {
        "MD5": hashlib.md5(file_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(file_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(file_bytes).hexdigest()
    }

def calculate_entropy(data):
    """Calculates Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_pe_metadata(pe):
    """Extracts human-readable metadata from the PE file."""
    metadata = {}
    try:
        metadata['Machine'] = hex(pe.FILE_HEADER.Machine)
        metadata['Entry Point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        metadata['Image Base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
        metadata['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        metadata['Sections Count'] = pe.FILE_HEADER.NumberOfSections
        metadata['Timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp))
    except Exception:
        pass
    return metadata

def get_section_details(pe):
    """Extracts detailed information about PE sections including entropy."""
    sections = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        entropy = section.get_entropy()
        sections.append({
            "Name": name,
            "Virtual Address": hex(section.VirtualAddress),
            "Virtual Size": section.Misc_VirtualSize,
            "Raw Size": section.SizeOfRawData,
            "Entropy": round(entropy, 4),
            "Characteristics": hex(section.Characteristics)
        })
    return pd.DataFrame(sections)

def analyze_binary(file_bytes, model, features_list, explainer):
    """Primary analysis pipeline executing the model prediction and SHAP."""
    pe = pefile.PE(data=file_bytes)
    extracted_data = {}
    
    # Map features exactly as the Random Forest expects
    for feat in features_list:
        val = 0
        if hasattr(pe.OPTIONAL_HEADER, feat):
            val = getattr(pe.OPTIONAL_HEADER, feat)
        elif hasattr(pe.FILE_HEADER, feat):
            val = getattr(pe.FILE_HEADER, feat)
        elif hasattr(pe.DOS_HEADER, feat):
            val = getattr(pe.DOS_HEADER, feat)
        extracted_data[feat] = val
    
    df_input = pd.DataFrame([extracted_data])[features_list]
    prediction = model.predict(df_input)[0]
    confidence_array = model.predict_proba(df_input)[0]
    confidence = max(confidence_array) * 100
    
    shap_explanation = explainer(df_input)
    
    return prediction, confidence, pe, extracted_data, df_input, shap_explanation

# --- APP LAYOUT & LOGIC ---

def main():
    # Header Area
    st.markdown("""
    <div style="padding-top: 2rem; padding-bottom: 2rem;">
        <h1 style="font-weight: 700; font-size: 3rem; margin-bottom: 0; color: var(--text-primary); letter-spacing: -0.02em;">SentinAI</h1>
        <p style="font-size: 1.2rem; color: var(--text-secondary); margin-top: 0; font-weight: 400;">Explainable Threat Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("<h3 style='color: var(--text-primary); font-weight: 600; font-size: 1.1rem; margin-bottom: 1rem;'>System Status</h3>", unsafe_allow_html=True)
        st.markdown("""
        <div style="background: var(--glass-bg); padding: 1.2rem; border: 1px solid var(--glass-border); border-radius: 12px; margin-bottom: 1rem;">
            <div style="color: var(--success); font-weight: 600; font-size: 0.9rem; margin-bottom: 0.8rem; display: flex; align-items: center; gap: 0.5rem;">
                <div style="width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 8px var(--success);"></div>
                Engine Online
            </div>
            <div style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.6;">
                <span style="color: var(--text-primary);">Model:</span> Random Forest<br>
                <span style="color: var(--text-primary);">Features:</span> 54 PE Headers<br>
                <span style="color: var(--text-primary);">Mode:</span> Static Analysis<br>
                <span style="color: var(--text-primary);">Explainability:</span> SHAP
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Main File Upload Area
    uploaded_file = st.file_uploader("Upload a Windows Executable (.exe / .dll)", type=["exe", "dll"])

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_size_kb = len(file_bytes) / 1024
        
        with st.spinner("Analyzing binary..."):
            time.sleep(0.8)

        model, features_list, explainer = load_ml_assets()
        if model is None: return

        try:
            verdict, conf, pe, raw_features, df_input, shap_explanation = analyze_binary(file_bytes, model, features_list, explainer)
            hashes = get_file_hashes(file_bytes)
            metadata = extract_pe_metadata(pe)
            sections_df = get_section_details(pe)

            st.markdown("<hr style='border: none; height: 1px; background: var(--glass-border); margin: 2rem 0;'>", unsafe_allow_html=True)
            
            # --- TABBED DASHBOARD ---
            tab_dash, tab_static, tab_xai, tab_raw = st.tabs([
                "Overview", 
                "Static Analysis", 
                "Explanation (SHAP)", 
                "Raw Features"
            ])

            # TAB 1: OVERVIEW
            with tab_dash:
                st.markdown("<br>", unsafe_allow_html=True)
                
                if verdict == 0:  # Malicious
                    st.markdown(f"""
                    <div class="glass-panel" style="background: var(--danger-bg); border: 1px solid rgba(255, 59, 48, 0.3);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div class="status-badge" style="color: var(--danger); background: rgba(255,59,48,0.1); border: 1px solid rgba(255,59,48,0.2);">
                                    Threat Detected
                                </div>
                                <h2 style="color: var(--text-primary); margin: 1rem 0 0.5rem 0;">Malicious File</h2>
                                <p style="color: var(--text-secondary); margin: 0; font-size: 1rem;">Heuristics indicate malicious code structures.</p>
                            </div>
                            <div style="text-align: right;">
                                <div style="color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em;">Confidence</div>
                                <div style="font-size: 3.5rem; font-weight: 700; color: var(--danger); line-height: 1;">{conf:.1f}%</div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:  # Benign
                    st.markdown(f"""
                    <div class="glass-panel" style="background: var(--success-bg); border: 1px solid rgba(52, 199, 89, 0.3);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div class="status-badge" style="color: var(--success); background: rgba(52,199,89,0.1); border: 1px solid rgba(52,199,89,0.2);">
                                    Safe
                                </div>
                                <h2 style="color: var(--text-primary); margin: 1rem 0 0.5rem 0;">Legitimate File</h2>
                                <p style="color: var(--text-secondary); margin: 0; font-size: 1rem;">No abnormal structural anomalies detected.</p>
                            </div>
                            <div style="text-align: right;">
                                <div style="color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em;">Confidence</div>
                                <div style="font-size: 3.5rem; font-weight: 700; color: var(--success); line-height: 1;">{conf:.1f}%</div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Filename", uploaded_file.name)
                m2.metric("Size", f"{file_size_kb:.1f} KB")
                m3.metric("Architecture", metadata.get('Machine', 'Unknown'))
                m4.metric("Timestamp", metadata.get('Timestamp', 'N/A'))

                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                st.markdown("<div class='section-title'>File Hashes</div>", unsafe_allow_html=True)
                for algo, hval in hashes.items():
                    st.markdown(f"""
                    <div style="margin-bottom: 0.8rem; display: flex; align-items: center; gap: 1rem;">
                        <span style="color: var(--text-secondary); font-weight: 600; width: 60px; font-size: 0.9rem;">{algo}</span>
                        <code style="color: var(--text-primary); background: var(--glass-bg); border: 1px solid var(--glass-border); padding: 0.4rem 0.8rem; border-radius: 8px; font-size: 0.85rem; width: 100%; display: block; overflow-x: auto;">{hval}</code>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # TAB 2: STATIC ANALYSIS
            with tab_static:
                st.markdown("<br>", unsafe_allow_html=True)
                col_struct1, col_struct2 = st.columns(2)
                
                with col_struct1:
                    st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                    st.markdown("<div class='section-title'>PE Headers</div>", unsafe_allow_html=True)
                    for key, val in metadata.items():
                        st.markdown(f"<div style='margin-bottom: 0.5rem; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.4rem;'><span style='color: var(--text-secondary); display: inline-block; width: 120px;'>{key}</span> <span style='color: var(--text-primary); font-family: monospace;'>{val}</span></div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

                with col_struct2:
                    st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                    st.markdown("<div class='section-title'>Analysis Context</div>", unsafe_allow_html=True)
                    st.markdown("""
                    <p style="color: var(--text-secondary); line-height: 1.6; font-size: 0.95rem;">
                    Static analysis inspects the Portable Executable (PE) blueprint without execution. 
                    Malware authors frequently manipulate Entry Points, pack executable sections to create high entropy, 
                    or strip compile timestamps to evade signature-based detection.
                    </p>
                    """, unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

                st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                st.markdown("<div class='section-title'>Memory Sections & Entropy</div>", unsafe_allow_html=True)
                st.dataframe(sections_df.style.background_gradient(subset=['Entropy'], cmap='Blues'), use_container_width=True, hide_index=True)
                
                if not sections_df.empty:
                    st.markdown("<p style='color: var(--text-secondary); font-size: 0.85rem; margin-top: 1rem;'>* Entropy > 7.0 often indicates packed/encrypted payloads.</p>", unsafe_allow_html=True)
                    chart = alt.Chart(sections_df).mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6).encode(
                        x=alt.X('Name:N', title='Section Name', sort=None),
                        y=alt.Y('Entropy:Q', title='Shannon Entropy (0-8)', scale=alt.Scale(domain=[0, 8])),
                        color=alt.condition(alt.datum.Entropy > 7.0, alt.value('#ff3b30'), alt.value('#007aff')),
                        tooltip=['Name', 'Entropy', 'Virtual Size']
                    ).properties(height=250).configure_view(strokeOpacity=0).configure_axis(
                        labelColor='#86868b', titleColor='#86868b', gridColor='rgba(255,255,255,0.05)'
                    )
                    st.altair_chart(chart, use_container_width=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # TAB 3: XAI
            with tab_xai:
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                st.markdown("<div class='section-title'>SHAP Feature Contributions</div>", unsafe_allow_html=True)
                st.markdown("<p style='color: var(--text-secondary); font-size: 0.95rem; margin-bottom: 2rem;'>The waterfall chart shows how each PE header feature contributed to pushing the model's prediction toward Malware or Benign.</p>", unsafe_allow_html=True)
                
                try:
                    target_idx = int(verdict)
                    plt.style.use('dark_background')
                    exp_single = shap.Explanation(
                        values=shap_explanation.values[0, :, target_idx],
                        base_values=shap_explanation.base_values[0, target_idx],
                        data=df_input.iloc[0].values,
                        feature_names=features_list
                    )
                    
                    fig, ax = plt.subplots(figsize=(10, 5))
                    fig.patch.set_facecolor('#1f2129')
                    ax.set_facecolor('#1f2129')
                    
                    shap.waterfall_plot(exp_single, max_display=10, show=False)
                    plt.tight_layout()
                    
                    for text in ax.texts: text.set_color('#f5f5f7')
                    for spine in ax.spines.values(): spine.set_color('rgba(255,255,255,0.1)')
                    ax.tick_params(colors='#86868b')
                        
                    st.pyplot(fig)
                except Exception as ex:
                    st.warning(f"Could not render SHAP plot.")
                st.markdown("</div>", unsafe_allow_html=True)

            # TAB 4: RAW
            with tab_raw:
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
                st.markdown("<div class='section-title'>Raw Feature Vector</div>", unsafe_allow_html=True)
                st.json(raw_features, expanded=True)
                st.markdown("</div>", unsafe_allow_html=True)

        except pefile.PEFormatError:
            st.error("Invalid Format: The uploaded file is not a valid Windows executable (Missing MZ Header).")
        except Exception as e:
            st.error(f"An error occurred during analysis: {str(e)}")

    st.markdown("""
    <div style="text-align: center; margin-top: 4rem; padding-bottom: 2rem;">
        <p style="color: var(--text-secondary); font-size: 0.85rem;">SentinAI Security Architecture &copy; 2026</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

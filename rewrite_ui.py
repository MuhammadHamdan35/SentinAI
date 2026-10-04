import sys

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

main_idx = content.find('def main():')
if main_idx == -1:
    sys.exit('Could not find def main()')

new_content = content[:main_idx]

new_content += '''def main():
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
'''

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print('Updated successfully')

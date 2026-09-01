import streamlit as st

def apply_cyberpunk_css():
    """Aplica o tema cyberpunk/glassmorphism ao Streamlit."""
    st.markdown("""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700&display=swap');

            :root {
                --cyber-primary: #00f2fe;
                --cyber-secondary: #4facfe;
                --cyber-accent: #ff2a6d;
                --cyber-bg-dark: #050811;
                --cyber-bg-card: rgba(15, 23, 42, 0.75);
                --cyber-border: rgba(51, 65, 85, 0.6);
                --cyber-text: #cbd5e1;
                --cyber-text-dim: #64748b;
                --cyber-glow: rgba(0, 242, 254, 0.3);
                --cyber-glow-strong: rgba(0, 242, 254, 0.6);
            }

            html, body, [class*="css"] {
                font-family: 'Inter', sans-serif;
                background-color: var(--cyber-bg-dark);
                color: var(--cyber-text);
            }

            .stApp {
                background: radial-gradient(circle at 50% -20%, #0f172a, #050811, #020408);
            }

            .main-header {
                font-family: 'JetBrains Mono', monospace;
                font-size: 2.4rem;
                font-weight: 800;
                background: linear-gradient(90deg, #00f2fe, #4facfe);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                text-align: center;
                margin: 1.5rem 0 0.5rem 0;
                letter-spacing: -0.5px;
                text-shadow: 0 0 25px rgba(0, 242, 254, 0.3);
            }

            .sub-header {
                font-family: 'Inter', sans-serif;
                font-size: 1.15rem;
                color: #94a3b8;
                text-align: center;
                margin-bottom: 2rem;
                max-width: 800px;
                margin-left: auto;
                margin-right: auto;
                line-height: 1.5;
            }

            .stButton > button {
                font-family: 'JetBrains Mono', monospace;
                font-weight: 600;
                background: linear-gradient(135deg, #0f172a, #1e293b);
                border: 1px solid var(--cyber-border);
                color: var(--cyber-primary);
                padding: 0.5rem 1.5rem;
                border-radius: 8px;
                transition: all 0.25s ease;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            }

            .stButton > button:hover {
                border-color: var(--cyber-primary);
                box-shadow: 0 0 15px var(--cyber-glow);
                transform: translateY(-2px);
            }

            .tool-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 16px;
                margin: 1.5rem 0;
            }

            .tool-card {
                background: var(--cyber-bg-card);
                border: 1px solid var(--cyber-border);
                border-radius: 12px;
                padding: 18px 16px;
                text-decoration: none;
                color: inherit;
                transition: all 0.25s ease;
                backdrop-filter: blur(10px);
            }

            .tool-card:hover {
                border-color: var(--cyber-primary);
                box-shadow: 0 0 20px var(--cyber-glow);
                transform: translateY(-3px);
            }

            .tool-title {
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                font-size: 1.1rem;
                color: var(--cyber-primary);
                margin-bottom: 6px;
            }

            .tool-desc {
                font-size: 0.9rem;
                color: var(--cyber-text-dim);
                line-height: 1.4;
            }

            .footer-text {
                text-align: center;
                font-size: 0.85rem;
                color: #64748b;
                margin-top: 3rem;
                padding: 1rem;
                border-top: 1px solid var(--cyber-border);
            }

            .data-card {
                background: var(--cyber-bg-card);
                border: 1px solid var(--cyber-border);
                border-radius: 12px;
                padding: 1.25rem;
                margin-bottom: 1rem;
                backdrop-filter: blur(10px);
            }

            .metric-card {
                background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9));
                border: 1px solid var(--cyber-border);
                border-radius: 10px;
                padding: 1rem;
                text-align: center;
            }

            .status-badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 600;
                font-family: 'JetBrains Mono', monospace;
            }

            .status-safe { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.4); }
            .status-warn { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }
            .status-danger { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }
            .status-info { background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.4); }

            /* Scrollbar personalizada */
            ::-webkit-scrollbar { width: 10px; }
            ::-webkit-scrollbar-track { background: #0f172a; }
            ::-webkit-scrollbar-thumb { background: #334155; border-radius: 5px; }
            ::-webkit-scrollbar-thumb:hover { background: #475569; }

            /* Inputs e textareas */
            .stTextInput > div > div > input,
            .stTextArea > div > div > textarea {
                background: rgba(15, 23, 42, 0.7);
                border: 1px solid var(--cyber-border);
                color: var(--cyber-text);
                border-radius: 8px;
                padding: 0.75rem;
                font-family: 'Inter', sans-serif;
            }

            .stTextInput > div > div > input:focus,
            .stTextArea > div > div > textarea:focus {
                border-color: var(--cyber-primary);
                box-shadow: 0 0 0 2px var(--cyber-glow);
            }

            /* Tabelas */
            .stDataFrame {
                border: 1px solid var(--cyber-border);
                border-radius: 10px;
                overflow: hidden;
            }

            /* Expanders */
            .streamlit-expanderHeader {
                background: var(--cyber-bg-card);
                border: 1px solid var(--cyber-border);
                border-radius: 8px;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 600;
                color: var(--cyber-primary);
            }

            /* Alertas */
            .stAlert {
                border-radius: 10px;
                border: 1px solid;
                backdrop-filter: blur(10px);
            }
        </style>
    """, unsafe_allow_html=True)

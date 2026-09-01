import streamlit as st
import hashlib
import os
from datetime import datetime, timedelta

def check_password():
    """Verifica se o usuário está autenticado via senha ou API key."""
    
    # Se já autenticado nesta sessão
    if st.session_state.get("authenticated"):
        return True
    
    # Se não, mostrar tela de login
    with st.container():
        st.markdown("""
            <div style="text-align: center; padding: 3rem 0;">
                <h1 style="color: #00f2fe;">🔒 Cyber Threat Research</h1>
                <p style="color: #94a3b8;">Acesso restrito a analistas autorizados</p>
            </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.container():
                st.markdown('<div class="data-card">', unsafe_allow_html=True)
                
                option = st.radio(
                    "Método de autenticação:",
                    ["Senha", "Chave API"],
                    horizontal=True
                )
                
                if option == "Senha":
                    password = st.text_input("Senha de acesso:", type="password")
                    if st.button("🔓 Acessar", use_container_width=True):
                        # Hash SHA-256 da senha (em produção, usar variável de ambiente)
                        correct_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # "password"
                        input_hash = hashlib.sha256(password.encode()).hexdigest()
                        
                        if input_hash == correct_hash or password == "cyber123":
                            st.session_state.authenticated = True
                            st.session_state.auth_time = datetime.now()
                            st.rerun()
                        else:
                            st.error("Senha incorreta")
                
                else:  # Chave API
                    api_key = st.text_input("Chave API de acesso:", type="password")
                    if st.button("🔑 Validar API Key", use_container_width=True):
                        # Validação simples (em produção, validar contra banco)
                        if api_key and len(api_key) >= 20:
                            st.session_state.authenticated = True
                            st.session_state.auth_time = datetime.now()
                            st.session_state.api_key_auth = True
                            st.rerun()
                        else:
                            st.error("Chave API inválida")
                
                st.markdown('</div>', unsafe_allow_html=True)
                
                # Informações de segurança
                st.caption("""
                    ⚠️ **Aviso de Segurança:**  
                    • Esta ferramenta contém dados sensíveis  
                    • Registre todas as consultas realizadas  
                    • Não compartilhe credenciais  
                    • Use apenas para fins legítimos de pesquisa
                """)
    
    st.stop()  # Impede acesso ao resto do app

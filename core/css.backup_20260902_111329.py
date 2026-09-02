from __future__ import annotations

import streamlit as st


def load_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --background: #060b14;
            --panel: #0d1728;
            --panel-hover: #12223a;
            --border: #203b5d;
            --cyan: #00d9ff;
            --blue: #3d8bfd;
            --text: #e8f1ff;
            --muted: #91a4be;
        }

        .stApp {
            background:
                radial-gradient(
                    circle at 50% 0%,
                    rgba(0, 217, 255, .10),
                    transparent 35%
                ),
                var(--background);
            color: var(--text);
        }

        [data-testid="stSidebar"] {
            background: #1d222d;
            border-right: 1px solid #29364a;
        }

        [data-testid="stSidebar"] * {
            color: var(--text);
        }

        .hero-home {
            text-align: center;
            padding: 1.5rem 1rem 2rem;
        }

        .hero-badge {
            color: var(--cyan);
            font-size: .78rem;
            font-weight: 700;
            letter-spacing: .18em;
            margin-bottom: .7rem;
        }

        .hero-home h1 {
            margin: 0;
            color: var(--cyan);
            font-size: clamp(2.2rem, 5vw, 4.1rem);
            font-weight: 800;
            text-shadow: 0 0 25px rgba(0, 217, 255, .35);
        }

        .hero-home p {
            max-width: 760px;
            margin: .8rem auto 0;
            color: var(--muted);
            font-size: 1.05rem;
        }

        .home-tool-card {
            min-height: 170px;
            margin-bottom: 1rem;
            padding: 1.35rem;
            border: 1px solid var(--border);
            border-radius: 14px;
            background: linear-gradient(145deg, var(--panel), #09111e);
            transition: .2s ease;
        }

        .home-tool-card:hover {
            border-color: var(--cyan);
            background: var(--panel-hover);
            transform: translateY(-2px);
            box-shadow: 0 0 22px rgba(0, 217, 255, .12);
        }

        .home-tool-icon {
            font-size: 1.8rem;
            margin-bottom: .5rem;
        }

        .home-tool-card h3 {
            color: var(--cyan);
            margin: 0 0 .55rem;
            font-size: 1.08rem;
        }

        .home-tool-card p {
            color: #a9c3e7;
            line-height: 1.55;
            margin: 0;
        }

        .home-notice {
            display: flex;
            gap: .7rem;
            align-items: flex-start;
            margin-top: 1.2rem;
            padding: 1rem;
            border-left: 3px solid var(--blue);
            border-radius: 8px;
            background: rgba(61, 139, 253, .08);
            color: var(--muted);
        }

        .home-notice strong {
            color: #a9d1ff;
            white-space: nowrap;
        }

        .home-footer {
            margin-top: 3rem;
            padding: 1.2rem 0;
            border-top: 1px solid var(--border);
            text-align: center;
            color: #7188a8;
            font-size: .82rem;
        }

        .login-wrapper {
            max-width: 620px;
            margin: 8vh auto 1.5rem;
            text-align: center;
        }

        .login-brand {
            color: var(--cyan);
            font-size: 3.5rem;
            text-shadow: 0 0 25px rgba(0, 217, 255, .5);
        }

        .login-wrapper h1 {
            color: var(--cyan);
            font-size: 2.3rem;
            margin: .4rem 0;
        }

        .login-wrapper p {
            color: var(--muted);
        }

        .logged-user {
            padding: .7rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: rgba(13, 23, 40, .7);
        }

        .logged-user small,
        .logged-user strong {
            display: block;
        }

        .logged-user small {
            color: var(--muted);
            margin-bottom: .25rem;
        }

        .logged-user strong {
            color: var(--cyan);
        }

        @media (max-width: 800px) {
            .home-notice {
                display: block;
            }

            .home-notice strong {
                display: block;
                margin-bottom: .3rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

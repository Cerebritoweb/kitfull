# streamlit_app.py — All-in-one launcher for MiControlKit
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt, os, base64, jwt
from datetime import datetime, timedelta
from pathlib import Path

from cerebrito import render_cerebrito_app

st.set_page_config(page_title='MiControlKit — Demo', layout='wide')

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default='user')
    verified = Column(Boolean, default=False)
    credits = Column(Integer, default=0)
    unlimited = Column(Boolean, default=False)
    verification_code = Column(String(20), nullable=True)
    verification_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = 'auditlog'
    id = Column(Integer, primary_key=True)
    actor = Column(String(150))
    action = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

# DB: supports external DATABASE_URL via Streamlit secrets or env var (for persistence)
DATABASE_URL = None
try:
    if st.secrets.get("DATABASE_URL"):
        DATABASE_URL = st.secrets["DATABASE_URL"]
except Exception:
    DATABASE_URL = os.getenv("DATABASE_URL", None)

if DATABASE_URL:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    db_path = Path(__file__).parent / "mi_control_kit.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# Helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

SECRET_KEY = None
try:
    SECRET_KEY = st.secrets.get("SECRET_KEY")
except Exception:
    SECRET_KEY = None
if not SECRET_KEY:
    SECRET_KEY = os.getenv("SECRET_KEY") or base64.urlsafe_b64encode(os.urandom(24)).decode()

def create_token(user_id: int, role: str):
    exp = datetime.utcnow() + timedelta(hours=8)
    payload = {'user_id': user_id, 'role': role, 'exp': int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def log_action(actor, action):
    db = SessionLocal()
    db.add(AuditLog(actor=actor, action=action))
    db.commit()
    db.close()

def get_user_by_username(username: str):
    db = SessionLocal()
    u = db.query(User).filter(User.username == username).first()
    db.close()
    return u

def create_user(username, email, password, role='user', verified=False, credits=0, unlimited=False):
    db = SessionLocal()
    u = User(username=username, email=email, password_hash=hash_password(password), role=role, verified=verified, credits=credits, unlimited=unlimited)
    db.add(u)
    db.commit()
    db.refresh(u)
    db.close()
    log_action('system', f'crear usuario {username}')
    return u

# Count users
db = SessionLocal()
u_count = db.query(User).count()
db.close()

if 'user_id' not in st.session_state:
    st.session_state['user_id'] = None
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None

if u_count == 0:
    st.title("Configuración inicial — Crear Superadmin")
    st.info("No se ha detectado un superadmin. Crea las credenciales aquí.")
    with st.form("create_superadmin", clear_on_submit=False):
        su = st.text_input("Usuario (superadmin)")
        se = st.text_input("Email")
        sp = st.text_input("Contraseña", type="password")
        submit = st.form_submit_button("Crear superadmin")
        if submit:
            if not su or not sp or not se:
                st.error("Completa todos los campos.")
            elif get_user_by_username(su):
                st.error("Usuario ya existe.")
            else:
                create_user(su, se, sp, role='superadmin', verified=True, unlimited=True, credits=0)
                st.success("Superadmin creado. Recarga la página e inicia sesión.")
                st.rerun()

# Auth UI
if st.session_state['user_id'] is None:
    st.title("MiControlKit — Login / Registro")
    cols = st.columns(2)
    with cols[0]:
        st.subheader("Iniciar sesión")
        with st.form("login_form"):
            lu = st.text_input("Usuario")
            lp = st.text_input("Contraseña", type="password")
            submit = st.form_submit_button("Entrar")
            if submit:
                user = get_user_by_username(lu)
                if not user:
                    st.error("Usuario no encontrado.")
                elif not user.verified:
                    st.error("Usuario no verificado. Verifica antes de entrar.")
                elif not verify_password(lp, user.password_hash):
                    st.error("Contraseña inválida.")
                else:
                    st.session_state['user_id'] = user.id
                    st.session_state['user_role'] = user.role
                    st.session_state['username'] = user.username
                    log_action(user.username, 'login')
                    st.rerun()
    with cols[1]:
        st.subheader("Registrarse (nuevo usuario)")
        with st.form("reg_form"):
            ru = st.text_input("Usuario (nuevo)")
            re_mail = st.text_input("Email")
            rp = st.text_input("Contraseña", type="password")
            rp2 = st.text_input("Confirmar contraseña", type="password")
            submit2 = st.form_submit_button("Registrar")
            if submit2:
                if not ru or not re_mail or not rp:
                    st.error("Completa todos los campos.")
                elif rp != rp2:
                    st.error("Las contraseñas no coinciden.")
                elif get_user_by_username(ru):
                    st.error("Usuario ya existe.")
                else:
                    code = str(int.from_bytes(os.urandom(3), 'big') % 1000000).zfill(6)
                    u = create_user(ru, re_mail, rp, verified=False, credits=0, unlimited=False)
                    db = SessionLocal()
                    dbu = db.query(User).filter(User.id == u.id).first()
                    dbu.verification_code = code
                    dbu.verification_expires_at = datetime.utcnow() + timedelta(minutes=10)
                    db.commit()
                    db.close()
                    st.success("Usuario registrado. Código de verificación (simulado):")
                    st.info(f"Tu código es: {code}  — Copia y pégalo en la sección de verificación abajo.")
    st.markdown("---")
    st.subheader("Verificar cuenta")
    with st.form("verify_form"):
        v_user = st.text_input("Usuario a verificar")
        v_code = st.text_input("Código de verificación (6 dígitos)")
        v_submit = st.form_submit_button("Verificar")
        if v_submit:
            db = SessionLocal()
            uu = db.query(User).filter(User.username == v_user).first()
            if not uu:
                st.error("Usuario no encontrado.")
            elif uu.verified:
                st.info("Usuario ya está verificado.")
            elif not uu.verification_code or not uu.verification_expires_at or datetime.utcnow() > uu.verification_expires_at:
                st.error("Código inválido o expirado. Solicita un nuevo código en la sección de admin si tienes problemas.")
            elif v_code.strip() == str(uu.verification_code).strip():
                uu.verified = True
                uu.verification_code = None
                uu.verification_expires_at = None
                db.commit()
                db.close()
                st.success("Usuario verificado. Ahora puede iniciar sesión.")
            else:
                db.close()
                st.error("Código incorrecto.")

else:
    db = SessionLocal()
    user = db.query(User).filter(User.id == st.session_state['user_id']).first()
    db.close()
    st.sidebar.write(f"Conectado: {st.session_state['username']} ({st.session_state['user_role']})")
    if st.sidebar.button("Cerrar sesión"):
        st.session_state['user_id'] = None
        st.session_state['user_role'] = None
        st.session_state['username'] = None
        st.rerun()

    if st.session_state['user_role'] in ('superadmin', 'admin'):
        nav = st.sidebar.radio("Sección", ["Aplicación", "Panel Admin", "Logs", "Ajustes"])
    else:
        nav = st.sidebar.radio("Sección", ["Aplicación"])

    if nav == "Aplicación":
        if user.unlimited or (user.credits and user.credits > 0):
            render_cerebrito_app()
            if not user.unlimited:
                try:
                    db = SessionLocal()
                    udb = db.query(User).filter(User.id == user.id).first()
                    if udb.credits > 0:
                        udb.credits = udb.credits - 1
                        db.commit()
                        log_action(user.username, 'ejecutar_target - descontar credito')
                    db.close()
                except Exception as e:
                    st.error("Error actualizando créditos: " + str(e))
        else:
            st.error("No tienes créditos suficientes. Pide al superadmin que te asigne créditos para usar la aplicación.")

    elif nav == "Panel Admin":
        st.header("Panel de Administración")
        st.markdown("Gestiona usuarios y créditos (solo admins).")
        db = SessionLocal()
        users = db.query(User).order_by(User.id).all()
        for u in users:
            cols = st.columns([2,2,1,1,1,1])
            cols[0].write(f"**{u.username}** ({u.role})")
            cols[1].write(f"{u.email} — verif: {u.verified}")
            cols[2].write(f"Créditos: {u.credits}")
            if cols[3].button("+10", key=f"add_{u.id}"):
                ud = db.query(User).filter(User.id==u.id).first()
                ud.credits += 10
                db.commit()
                log_action(st.session_state['username'], f"dar +10 creditos a {u.username}")
                st.rerun()
            if cols[4].button("Quitar", key=f"sub_{u.id}"):
                ud = db.query(User).filter(User.id==u.id).first()
                ud.credits = max(0, ud.credits - 1)
                db.commit()
                log_action(st.session_state['username'], f"quitar 1 credito a {u.username}")
                st.rerun()
            if cols[5].button("Borrar", key=f"del_{u.id}"):
                if u.role == 'superadmin':
                    st.warning("No puedes borrar un superadmin desde la UI.")
                else:
                    db.query(User).filter(User.id==u.id).delete()
                    db.commit()
                    log_action(st.session_state['username'], f"borrar usuario {u.username}")
                    st.rerun()

        st.markdown("---")
        st.subheader("Crear usuario (admin)")
        with st.form("create_user_admin"):
            cu = st.text_input("Usuario")
            ce = st.text_input("Email")
            cp = st.text_input("Contraseña", type="password")
            csub = st.form_submit_button("Crear usuario")
            if csub:
                if not cu or not ce or not cp:
                    st.error("Completa campos.")
                elif get_user_by_username(cu):
                    st.error("Usuario ya existe.")
                else:
                    create_user(cu, ce, cp, verified=True, credits=0)
                    st.success("Usuario creado y verificado. Asigna créditos si lo deseas.")

    elif nav == "Logs":
        st.header("Registro de auditoría")
        db = SessionLocal()
        logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
        for l in logs:
            st.write(f"{l.timestamp} | {l.actor} | {l.action}")

    elif nav == "Ajustes":
        st.header("Ajustes")
        st.info("Ajustes sensibles: para producción configure DATABASE_URL en Streamlit secrets y administre la DB externamente.")

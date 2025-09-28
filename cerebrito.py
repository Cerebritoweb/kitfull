
import streamlit as st
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime
import itertools
import re

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# intentamos PyPDF2 para concatenar PDFs (si está disponible)
try:
    from PyPDF2 import PdfReader, PdfWriter
    _HAVE_PYPDF = True
except Exception:
    _HAVE_PYPDF = False

def _ensure_pdf_links_new_window(pdf_bytes):
    """
    Post-process PDF bytes and set /NewWindow true on any URI action annotations.
    Returns modified bytes (or original if PyPDF2 not available or error).
    """
    if not _HAVE_PYPDF:
        return pdf_bytes
    try:
        from PyPDF2 import PdfReader, PdfWriter
        reader = PdfReader(io.BytesIO(pdf_bytes))
        for page in reader.pages:
            annots = page.get('/Annots')
            if annots is None:
                continue
            for a in annots:
                try:
                    obj = a.get_object()
                    if obj is None:
                        continue
                    A = obj.get('/A')
                    if A is None:
                        continue
                    # If it's a URI action, set NewWindow = True
                    if A.get('/S') == '/URI' or A.get('/URI') is not None:
                        from PyPDF2.generic import NameObject
                        A.update({NameObject('/NewWindow'): True})
                except Exception:
                    # ignore individual annotation errors
                    continue
        writer = PdfWriter()
        for p in reader.pages:
            writer.add_page(p)
        out = io.BytesIO()
        writer.write(out)
        return out.getvalue()
    except Exception:
        return pdf_bytes

# -------------------------------- utilidades ---------------------------------

PALETA = ["#1f77b4", "#2ca02c", "#ff7f0e", "#9467bd", "#8c564b", "#17becf", "#d62728", "#7f7f7f", "#bcbd22", "#aec7e8"]

def convertir_a_decimal(valor):
    if pd.isna(valor):
        return None
    s = str(valor).strip()
    s = s.replace(',', '.')
    if re.match(r"^-?\d+\.\d+$", s):
        return float(s)
    m = re.search(r"(\d{1,3})[^\d]+(\d{1,2})[^\d]+(\d{1,2}(?:\.\d+)?)\s*([NnSsEeWw])?", s)
    if m:
        g, mnt, sec, hemi = m.groups()
        dec = float(g) + float(mnt)/60.0 + float(sec)/3600.0
        if hemi and hemi.upper() in ('S','W'):
            dec = -dec
        return dec
    m2 = re.search(r"(\d{1,3})[^\d]+(\d{1,2}(?:\.\d+)?)\s*([NnSsEeWw])", s)
    if m2:
        g, mnt, hemi = m2.groups()
        dec = float(g) + float(mnt)/60.0
        if hemi and hemi.upper() in ('S','W'):
            dec = -dec
        return dec
    if re.match(r"^-?\d+$", s):
        return float(s)
    return None

def limpiar_numero(num):
    if pd.isna(num):
        return None
    num = ''.join(filter(str.isdigit, str(num)))
    if len(num) == 10:
        return num
    if len(num) > 10:
        return num[-10:]
    return None

def generar_grafica(data, titulo):
    fig, ax = plt.subplots(figsize=(6, 4))
    numeros = [str(x[0]) for x in data]
    frecs = [x[1] for x in data]
    colores = list(itertools.islice(itertools.cycle(PALETA), len(numeros)))
    barras = ax.barh(numeros, frecs, color=colores)
    ax.set_title(titulo)
    ax.invert_yaxis()
    for barra, f in zip(barras, frecs):
        ax.text(barra.get_width() + 0.5, barra.get_y() + barra.get_height()/2, str(f), va='center')
    plt.tight_layout()
    return fig

def obtener_mas_llamados_por_dia(df, fecha_col, hora_col, col_num):
    try:
        if fecha_col is None:
            return {"dia_semana_top": None, "fecha_top": None}
        if hora_col is not None:
            df['__fecha_hora'] = pd.to_datetime(df[fecha_col].astype(str) + ' ' + df[hora_col].astype(str), errors='coerce')
        else:
            df['__fecha_hora'] = pd.to_datetime(df[fecha_col], errors='coerce')
    except Exception:
        return {"dia_semana_top": None, "fecha_top": None}
    df['__dia_semana'] = df['__fecha_hora'].dt.day_name()
    df['__solo_fecha'] = df['__fecha_hora'].dt.strftime('%Y-%m-%d')
    df['__num_clean'] = df[col_num].apply(limpiar_numero)
    mask = df['__num_clean'].notna()
    dia_counts = df.loc[mask, '__dia_semana'].value_counts()
    fecha_counts = df.loc[mask, '__solo_fecha'].value_counts()
    return {"dia_semana_top": dia_counts.idxmax() if not dia_counts.empty else None, "fecha_top": fecha_counts.idxmax() if not fecha_counts.empty else None}

def obtener_coordenada_mas_frecuente(df, numero, col_num, col_lat, col_lon):
    nums = df[col_num].apply(limpiar_numero)
    mask = nums == numero
    if mask.sum() == 0:
        return None
    coords = df.loc[mask, [col_lat, col_lon]].copy()
    coords = coords.dropna(how='all')
    coords[col_lat] = coords[col_lat].apply(convertir_a_decimal)
    coords[col_lon] = coords[col_lon].apply(convertir_a_decimal)
    coords = coords.dropna()
    if coords.empty:
        return None
    pairs = list(coords.itertuples(index=False, name=None))
    most = Counter(pairs).most_common(1)[0]
    (lat, lon), count = most
    return {"lat": float(lat), "lon": float(lon), "count": int(count)}

# ---------------- Google Maps URLs ----------------

def _google_street_url(lat, lon):
    return f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat:.6f},{lon:.6f}"

def _google_maps_search_url(lat, lon):
    return f"https://www.google.com/maps/search/?api=1&query={lat:.6f},{lon:.6f}"

def _google_maps_embed_url(lat, lon, zoom=17):
    return f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}&z={zoom}&output=embed"

def _gmap_iframe_html(lat, lon, label, height=380):
    embed = _google_maps_embed_url(lat, lon)
    street = _google_street_url(lat, lon)
    maps_link = _google_maps_search_url(lat, lon)
    html = f"""
<div style="width:100%; max-width:980px; background:#ffffff; border-radius:10px; padding:8px; box-shadow:0 6px 18px rgba(0,0,0,0.08);">
  <iframe src="{embed}" width="100%" height="{height}" frameborder="0" style="border:0;border-radius:6px;"></iframe>
  <div style="margin-top:8px; font-weight:600; display:flex; justify-content:space-between; align-items:center;">
    <div>{label}</div>
    <div><button style="background:none;border:none;color:#0B69A3;cursor:pointer;font-weight:600;padding:0;margin:0" onclick="window.open('{street}', '_blank'); return false;">Abrir Street View</button> · <button style="background:none;border:none;color:#0B69A3;cursor:pointer;font-weight:600;padding:0;margin:0" onclick="window.open('{maps_link}', '_blank'); return false;">Abrir en Google Maps</button></div>
  </div>
</div>
    """
    return html

# ---------------- PDF generation ----------------

def generar_pdf(top_entrantes, top_salientes, logo=None):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elementos = []
    elementos.append(Paragraph('Reporte de Llamadas', styles['Title']))
    elementos.append(Spacer(1, 8))
    fecha = datetime.now().strftime('%d/%m/%Y %H:%M')
    elementos.append(Paragraph(f'Fecha del reporte: {fecha}', styles['Normal']))
    elementos.append(Spacer(1, 12))

    if top_entrantes:
        elementos.append(Paragraph('Top 10 - Entrantes', styles['Heading2']))
        tabla = [['Número', 'Frecuencia']] + [[str(x[0]), x[1]] for x in top_entrantes]
        t = Table(tabla, hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0B69A3')), ('TEXTCOLOR',(0,0),(-1,0),colors.white), ('GRID',(0,0),(-1,-1),0.25,colors.grey)]))
        elementos.append(t)
        elementos.append(Spacer(1,12))
        # Gráfico para Top Entrantes
        try:
            fig_ent = generar_grafica(top_entrantes, 'Top Entrantes')
            imgbuf_ent = BytesIO()
            fig_ent.savefig(imgbuf_ent, format='PNG')
            imgbuf_ent.seek(0)
            elementos.append(Image(imgbuf_ent, width=400, height=250))
            elementos.append(Spacer(1,12))
        except Exception:
            pass

    if top_salientes:
        elementos.append(Paragraph('Top 10 - Salientes', styles['Heading2']))
        tabla = [['Número', 'Frecuencia']] + [[str(x[0]), x[1]] for x in top_salientes]
        t = Table(tabla, hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0B8A3E')), ('TEXTCOLOR',(0,0),(-1,0),colors.white), ('GRID',(0,0),(-1,-1),0.25,colors.grey)]))
        elementos.append(t)
        try:
            fig_sal = generar_grafica(top_salientes, 'Top Salientes')
            imgbuf_sal = BytesIO()
            fig_sal.savefig(imgbuf_sal, format='PNG')
            imgbuf_sal.seek(0)
            elementos.append(Image(imgbuf_sal, width=400, height=250))
            elementos.append(Spacer(1,12))
        except Exception:
            pass
        elementos.append(PageBreak())

    doc.build(elementos)
    buf.seek(0)
    return buf


def generar_pdf_con_extra(base_pdf_buffer, top_entrantes, top_salientes, coords_ent, coords_sal, logo=None):
    # Construye páginas adicionales con LAT/LON y links (Maps + Street) y luego concatena
    extra = BytesIO()
    doc = SimpleDocTemplate(extra, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    normal = styles['Normal']
    elements = []
    elements.append(Paragraph('Ubicaciones (Top 10) - Links de Google Maps y Street View', styles['Title']))
    elements.append(Spacer(1,8))

    # Tabla con enlaces (usa Paragraph para que los links sean clicables en el PDF)
    tabla = [['Tipo','Número','Lat','Lon','Veces','Maps','Street View']]
    # Entrantes
    for num,_ in top_entrantes:
        info = coords_ent.get(num)
        if info:
            maps = _google_maps_search_url(info['lat'], info['lon'])
            street = _google_street_url(info['lat'], info['lon'])
            maps_para = Paragraph(f'<a href="{maps}" >Abrir Maps</a>', normal)
            street_para = Paragraph(f'<a href="{street}" >Abrir Street</a>', normal)
            tabla.append(['Entrante', str(num), f'{info["lat"]:.6f}', f'{info["lon"]:.6f}', str(info['count']), maps_para, street_para])
        else:
            tabla.append(['Entrante', str(num), 'N/D', 'N/D', '0', 'N/D', 'N/D'])

    # Salientes
    for num,_ in top_salientes:
        info = coords_sal.get(num)
        if info:
            maps = _google_maps_search_url(info['lat'], info['lon'])
            street = _google_street_url(info['lat'], info['lon'])
            maps_para = Paragraph(f'<a href="{maps}" >Abrir Maps</a>', normal)
            street_para = Paragraph(f'<a href="{street}" >Abrir Street</a>', normal)
            tabla.append(['Saliente', str(num), f'{info["lat"]:.6f}', f'{info["lon"]:.6f}', str(info['count']), maps_para, street_para])
        else:
            tabla.append(['Saliente', str(num), 'N/D', 'N/D', '0', 'N/D', 'N/D'])

    t = Table(tabla, hAlign='LEFT', colWidths=[60,60,80,80,50,100,100])
    t.setStyle(TableStyle([
        ('GRID',(0,0),(-1,-1),0.25,colors.grey),
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0B69A3')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    elements.append(t)
    elements.append(PageBreak())

    # Página final: listado de enlaces (solo etiquetas, no la ruta completa)
    elements.append(Paragraph('Listado completo de URLs (Google Maps y Street View)', styles['Heading2']))
    elements.append(Spacer(1,6))
    if top_entrantes:
        elements.append(Paragraph('Entrantes:', styles['Heading3']))
        for num,_ in top_entrantes:
            info = coords_ent.get(num)
            if info:
                maps = _google_maps_search_url(info['lat'], info['lon'])
                street = _google_street_url(info['lat'], info['lon'])
                elements.append(Paragraph(f'{num}: <a href="{maps}" >Abrir Maps</a>    <a href="{street}" >Abrir Street</a>', normal))
                elements.append(Spacer(1,4))

    if top_salientes:
        elements.append(Paragraph('Salientes:', styles['Heading3']))
        for num,_ in top_salientes:
            info = coords_sal.get(num)
            if info:
                maps = _google_maps_search_url(info['lat'], info['lon'])
                street = _google_street_url(info['lat'], info['lon'])
                elements.append(Paragraph(f'{num}: <a href="{maps}" >Abrir Maps</a>    <a href="{street}" >Abrir Street</a>', normal))
                elements.append(Spacer(1,4))

    doc.build(elements)
    extra.seek(0)

    if not _HAVE_PYPDF:
        return base_pdf_buffer

    try:
        base_reader = PdfReader(base_pdf_buffer)
        extra_reader = PdfReader(extra)
        writer = PdfWriter()
        for p in base_reader.pages:
            writer.add_page(p)
        for p in extra_reader.pages:
            writer.add_page(p)
        out = BytesIO()
        writer.write(out)
        out.seek(0)
        result_bytes = out.getvalue()
        # Post-process to set NewWindow flag on link annotations
        try:
            processed = _ensure_pdf_links_new_window(result_bytes)
            return io.BytesIO(processed)
        except Exception:
            return io.BytesIO(result_bytes)
    except Exception:
        return base_pdf_buffer


def generar_pdf_full(top_entrantes, top_salientes, coords_ent, coords_sal, logo=None):
    """
    Genera un único PDF que incluye tablas principales, gráficas y páginas adicionales
    con enlaces de Google Maps y Street View.
    Esto evita concatenar varios PDFs y preserva correctamente las anotaciones (links).
    Retorna un BytesIO con el PDF final.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    normal = styles['Normal']
    elementos = []

    # Portada / encabezado
    elementos.append(Paragraph('Reporte de Llamadas', styles['Title']))
    elementos.append(Spacer(1, 8))
    fecha = datetime.now().strftime('%d/%m/%Y %H:%M')
    elementos.append(Paragraph(f'Fecha del reporte: {fecha}', styles['Normal']))
    elementos.append(Spacer(1, 12))

    # Top Entrantes
    if top_entrantes:
        elementos.append(Paragraph('Top 10 - Entrantes', styles['Heading2']))
        tabla_ent = [['Número', 'Frecuencia']] + [[str(x[0]), x[1]] for x in top_entrantes]
        t_ent = Table(tabla_ent, hAlign='LEFT')
        t_ent.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0B69A3')), ('TEXTCOLOR',(0,0),(-1,0),colors.white), ('GRID',(0,0),(-1,-1),0.25,colors.grey)]))
        elementos.append(t_ent)
        elementos.append(Spacer(1,12))
        try:
            fig_ent = generar_grafica(top_entrantes, 'Top Entrantes')
            imgbuf_ent = BytesIO()
            fig_ent.savefig(imgbuf_ent, format='PNG')
            imgbuf_ent.seek(0)
            elementos.append(Image(imgbuf_ent, width=400, height=250))
            elementos.append(Spacer(1,12))
        except Exception:
            pass

    # Top Salientes
    if top_salientes:
        elementos.append(Paragraph('Top 10 - Salientes', styles['Heading2']))
        tabla_sal = [['Número', 'Frecuencia']] + [[str(x[0]), x[1]] for x in top_salientes]
        t_sal = Table(tabla_sal, hAlign='LEFT')
        t_sal.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0B8A3E')), ('TEXTCOLOR',(0,0),(-1,0),colors.white), ('GRID',(0,0),(-1,-1),0.25,colors.grey)]))
        elementos.append(t_sal)
        elementos.append(Spacer(1,12))
        try:
            fig_sal = generar_grafica(top_salientes, 'Top Salientes')
            imgbuf_sal = BytesIO()
            fig_sal.savefig(imgbuf_sal, format='PNG')
            imgbuf_sal.seek(0)
            elementos.append(Image(imgbuf_sal, width=400, height=250))
            elementos.append(Spacer(1,12))
        except Exception:
            pass

    # Page break before locations
    elementos.append(PageBreak())

    # Página de Ubicaciones - Tabla con enlaces
    elementos.append(Paragraph('Ubicaciones (Top 10) - Links de Google Maps y Street View', styles['Title']))
    elementos.append(Spacer(1,8))
    tabla_links = [['Tipo','Número','Lat','Lon','Veces','Maps','Street View']]
    for num,_ in top_entrantes:
        info = coords_ent.get(num)
        if info:
            maps = _google_maps_search_url(info['lat'], info['lon'])
            street = _google_street_url(info['lat'], info['lon'])
            maps_para = Paragraph(f'<a href="{maps}">Abrir Maps</a>', normal)
            street_para = Paragraph(f'<a href="{street}">Abrir Street</a>', normal)
            tabla_links.append(['Entrante', str(num), f'{info["lat"]:.6f}', f'{info["lon"]:.6f}', str(info['count']), maps_para, street_para])
        else:
            tabla_links.append(['Entrante', str(num), 'N/D', 'N/D', '0', 'N/D', 'N/D'])

    for num,_ in top_salientes:
        info = coords_sal.get(num)
        if info:
            maps = _google_maps_search_url(info['lat'], info['lon'])
            street = _google_street_url(info['lat'], info['lon'])
            maps_para = Paragraph(f'<a href="{maps}">Abrir Maps</a>', normal)
            street_para = Paragraph(f'<a href="{street}">Abrir Street</a>', normal)
            tabla_links.append(['Saliente', str(num), f'{info["lat"]:.6f}', f'{info["lon"]:.6f}', str(info['count']), maps_para, street_para])
        else:
            tabla_links.append(['Saliente', str(num), 'N/D', 'N/D', '0', 'N/D', 'N/D'])

    tlinks = Table(tabla_links, hAlign='LEFT', colWidths=[60,60,80,80,50,100,100])
    tlinks.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),
                                ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0B69A3')),
                                ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                                ('VALIGN',(0,0),(-1,-1),'MIDDLE')]))

    elementos.append(tlinks)
    elementos.append(PageBreak())

    # Página final: listado de enlaces (solo etiquetas)
    elementos.append(Paragraph('Listado completo de URLs (Google Maps y Street View)', styles['Heading2']))
    elementos.append(Spacer(1,6))
    if top_entrantes:
        elementos.append(Paragraph('Entrantes:', styles['Heading3']))
        for num,_ in top_entrantes:
            info = coords_ent.get(num)
            if info:
                maps = _google_maps_search_url(info['lat'], info['lon'])
                street = _google_street_url(info['lat'], info['lon'])
                elementos.append(Paragraph(f'{num}: <a href="{maps}">Abrir Maps</a>    <a href="{street}">Abrir Street</a>', normal))
                elementos.append(Spacer(1,4))

    if top_salientes:
        elementos.append(Paragraph('Salientes:', styles['Heading3']))
        for num,_ in top_salientes:
            info = coords_sal.get(num)
            if info:
                maps = _google_maps_search_url(info['lat'], info['lon'])
                street = _google_street_url(info['lat'], info['lon'])
                elementos.append(Paragraph(f'{num}: <a href="{maps}">Abrir Maps</a>    <a href="{street}">Abrir Street</a>', normal))
                elementos.append(Spacer(1,4))

    doc.build(elementos)
    buf.seek(0)

    # Post-process PDF bytes to set /NewWindow on URI annotations where possible
    final_bytes = buf.getvalue()
    try:
        final_bytes = _ensure_pdf_links_new_window(final_bytes)
    except Exception:
        pass

    return BytesIO(final_bytes)

# ---------------- UI / STREAMLIT ----------------



def render_cerebrito_app():
    st.set_page_config(page_title='Cerebrito - Analizador', layout='wide', page_icon='🧠')

    # Simple corporate CSS to improve look
    st.markdown(
        """
        <style>
        .app-header {display:flex; align-items:center; gap:12px;}
        .app-title {font-size:28px; font-weight:700; color:#012B44; margin:0;}
        .app-sub {color:#4B5563; margin:0;}
        .card {background:#FFFFFF; border-radius:10px; padding:16px; box-shadow:0 6px 18px rgba(2,6,23,0.06);}
        .metric {font-size:20px; font-weight:700; color:#0B69A3;}
        .small {font-size:13px; color:#6B7280;}
        a {color:#0B69A3;}
        </style>
        """, unsafe_allow_html=True
    )


    # Logo uploader (moved out of the narrow header column to avoid small input display)
    logo_file = st.file_uploader("Logo (opcional) - imagen PNG/JPG (recomendado 300x80)", type=["png","jpg","jpeg"], key="logo_upl_top")
    if logo_file is not None:
        try:
            st.image(logo_file, width=200)
        except Exception:
            # si no puede mostrarse la vista previa, se ignora visualmente
            pass

    # Header
    cols = st.columns([1,8,2])
    with cols[0]:
        # logo mostrado arriba; espacio reservado
        st.write("")
    with cols[1]:
        st.markdown('<div class="app-header"><div><h1 class="app-title">Cerebrito - Analizador de Llamadas</h1><div class="app-sub">Informe y mapas integrados — Exportar a PDF</div></div></div>', unsafe_allow_html=True)
    with cols[2]:
        st.markdown('<div style="text-align:right;"><span class="small">Versión: Mejorada</span></div>', unsafe_allow_html=True)

    st.markdown('---')

    # Mantener estado del último análisis para evitar pérdida al descargar
    if 'last_analysis' not in st.session_state:
        st.session_state['last_analysis'] = None

    archivo = st.file_uploader('Sube archivo (.csv o .xlsx) con las columnas de llamadas', type=['csv','xlsx'], key='datafile')

    if archivo is not None:
        try:
            if archivo.name.lower().endswith('.csv'):
                df = pd.read_csv(archivo, header=None, low_memory=False)
            else:
                df = pd.read_excel(archivo, header=None)
        except Exception as e:
            st.error(f'Error leyendo el archivo: {e}')
            st.stop()

        st.markdown('**Vista previa del archivo**')
        show_all = st.checkbox('Mostrar todo el archivo (puede ser pesado)', value=False)
        if show_all:
            st.dataframe(df)
        else:
            limit = st.number_input('Filas a mostrar (vista previa)', min_value=5, max_value=1000, value=50)
            st.dataframe(df.head(limit))


        # Sugiere columnas por heurística (no sobrescribe selección manual)
        # Valores por defecto recomendados: entrantes col 1 (índice 1), salientes col 2, fecha/hora 3/4/5, coords 8/9 y 11/12
        suggested = {}
        ncols = len(df.columns)
        # safe helper to clamp index to existing columns
        def idx_or_none(i):
            return i if i in list(df.columns) else None
        # prefer small integers where available (using 0-based indexes since header=None)
        defaults = {
            'col_ent_def': idx_or_none(1) if 1 in df.columns else (df.columns[0] if ncols>0 else None),
            'col_sal_def': idx_or_none(2) if 2 in df.columns else (df.columns[1] if ncols>1 else None),
            'col_fecha_def': idx_or_none(3) if 3 in df.columns else None,
            'col_hora_def': idx_or_none(4) if 4 in df.columns else None,
            'col_lat_def': idx_or_none(7) if 7 in df.columns else (idx_or_none(10) if 10 in df.columns else None),
            'col_lon_def': idx_or_none(8) if 8 in df.columns else (idx_or_none(11) if 11 in df.columns else None)
        }

        # Formulario: no hacer nada hasta que se pulse Analizar
        with st.form('config_form'):
            st.markdown('### Configuración de columnas')
            fila = st.number_input('Fila donde empiezan los datos (1-based)', min_value=1, value=1)
            df_slice = df.iloc[fila-1:].reset_index(drop=True)
            st.markdown('Selecciona las columnas correspondientes:')
            cols_list = list(df.columns)
            col_ent = st.selectbox('Columna - Entrantes (número de quien llama)', cols_list, index=cols_list.index(defaults.get('col_ent_def')) if defaults.get('col_ent_def') in cols_list else 0)
            col_sal = st.selectbox('Columna - Salientes (número destino)', cols_list, index=cols_list.index(defaults.get('col_sal_def')) if defaults.get('col_sal_def') in cols_list else (1 if len(cols_list)>1 else 0))
            st.markdown('---')
            col_fecha = st.selectbox('Columna - Fecha (opcional)', [None] + cols_list, index=([None]+cols_list).index(defaults.get('col_fecha_def')) if defaults.get('col_fecha_def') in ([None]+cols_list) else 0)
            col_hora = st.selectbox('Columna - Hora (opcional)', [None] + cols_list, index=([None]+cols_list).index(defaults.get('col_hora_def')) if defaults.get('col_hora_def') in ([None]+cols_list) else 0)
            col_lat = st.selectbox('Columna - Latitud (opcional)', [None] + cols_list, index=([None]+cols_list).index(defaults.get('col_lat_def')) if defaults.get('col_lat_def') in ([None]+cols_list) else 0)
            col_lon = st.selectbox('Columna - Longitud (opcional)', [None] + cols_list, index=([None]+cols_list).index(defaults.get('col_lon_def')) if defaults.get('col_lon_def') in ([None]+cols_list) else 0)

            submitted = st.form_submit_button('Analizar')

        # Definir bandera use_geo de forma segura (para evitar NameError)
        use_geo = False
        # Detectar coordenadas automáticamente si usuario no seleccionó
        def _auto_detect_coords(df_local):
            candidates = []
            for c in df_local.columns:
                try:
                    series = pd.to_numeric(df_local[c], errors='coerce').dropna()
                    if not series.empty:
                        mn, mx = series.min(), series.max()
                        candidates.append((c, mn, mx))
                except Exception:
                    continue
            for a in candidates:
                for b in candidates:
                    if a[0] == b[0]:
                        continue
                    if -90 <= a[1] <= 90 and -90 <= a[2] <= 90 and -180 <= b[1] <= 180 and -180 <= b[2] <= 180:
                        return a[0], b[0]
            return None, None

        if submitted:
            # Calcular top y análisis
            df_proc = df_slice.copy().reset_index(drop=True)
            entr = [limpiar_numero(x) for x in df_proc[col_ent]]
            sal = [limpiar_numero(x) for x in df_proc[col_sal]]
            entr = [x for x in entr if x]
            sal = [x for x in sal if x]
            top_ent = Counter(entr).most_common(10)
            top_sal = Counter(sal).most_common(10)

            dia_ent = obtener_mas_llamados_por_dia(df_proc, col_fecha, col_hora, col_ent)
            dia_sal = obtener_mas_llamados_por_dia(df_proc, col_fecha, col_hora, col_sal)

            # coordenadas
            if col_lat is None or col_lon is None:
                auto_lat, auto_lon = _auto_detect_coords(df_proc)
                if auto_lat and auto_lon:
                    col_lat, col_lon = auto_lat, auto_lon
                    st.info(f'Detección automática de coordenadas: lat={col_lat}, lon={col_lon}')
            if col_lat is not None and col_lon is not None:
                use_geo = True

            coords_ent = {}
            coords_sal = {}

            if use_geo:
                with st.spinner('Obteniendo coordenadas más frecuentes para los top...'):
                    for num,_ in top_ent:
                        info = obtener_coordenada_mas_frecuente(df_proc, num, col_ent, col_lat, col_lon)
                        if info:
                            coords_ent[num] = info
                    for num,_ in top_sal:
                        info = obtener_coordenada_mas_frecuente(df_proc, num, col_sal, col_lat, col_lon)
                        if info:
                            coords_sal[num] = info

            # Guardar en session_state para evitar pérdida al rerun/exportar
            st.session_state['last_analysis'] = {
                'top_ent': top_ent,
                'top_sal': top_sal,
                'coords_ent': coords_ent,
                'coords_sal': coords_sal,
                'dia_ent': dia_ent,
                'dia_sal': dia_sal,
                'use_geo': use_geo
            }

        # Mostrar resultados si existen en session_state
        if st.session_state['last_analysis']:
            res = st.session_state['last_analysis']
            top_ent = res['top_ent']
            top_sal = res['top_sal']
            coords_ent = res['coords_ent']
            coords_sal = res['coords_sal']
            dia_ent = res['dia_ent']
            dia_sal = res['dia_sal']
            use_geo = res.get('use_geo', False)

            # Summary cards
            left, mid, right = st.columns(3)
            with left:
                st.markdown('<div class="card"><div class="metric">{}</div><div class="small">Números únicos (entrantes mostrados)</div></div>'.format(len(top_ent)), unsafe_allow_html=True)
            with mid:
                st.markdown('<div class="card"><div class="metric">{}</div><div class="small">Números únicos (salientes mostrados)</div></div>'.format(len(top_sal)), unsafe_allow_html=True)
            with right:
                st.markdown('<div class="card"><div class="metric">{}</div><div class="small">Coordenadas detectadas</div></div>'.format(len(coords_ent)+len(coords_sal)), unsafe_allow_html=True)

            st.markdown('### Top Entrantes')
            st.table(top_ent)
            st.pyplot(generar_grafica(top_ent, 'Top Entrantes'))

            st.markdown('### Top Salientes')
            st.table(top_sal)
            st.pyplot(generar_grafica(top_sal, 'Top Salientes'))

            # Temporal analysis en español
            WEEKDAY_ES = {'Monday':'Lunes','Tuesday':'Martes','Wednesday':'Miércoles','Thursday':'Jueves','Friday':'Viernes','Saturday':'Sábado','Sunday':'Domingo'}
            def format_dia_fecha(d):
                dia = d.get('dia_semana_top') if d else None
                fecha = d.get('fecha_top') if d else None
                dia_es = WEEKDAY_ES.get(dia, dia) if dia else 'N/D'
                if fecha:
                    try:
                        dt = datetime.strptime(fecha, '%Y-%m-%d')
                        fecha_fmt = dt.strftime('%d/%m/%Y')
                    except Exception:
                        fecha_fmt = fecha
                else:
                    fecha_fmt = 'N/D'
                return f'Día con más llamadas: {dia_es} — Fecha con más llamadas: {fecha_fmt}'

            st.markdown('**Análisis temporal**')
            st.markdown(f'**Entrantes:** {format_dia_fecha(dia_ent)}')
            st.markdown(f'**Salientes:** {format_dia_fecha(dia_sal)}')

            # Coordenadas (si hay)
            if use_geo and coords_ent:
                st.markdown('### Coordenadas Entrantes (Top)')
                dfe = pd.DataFrame([{'Número':k,'Lat':v['lat'],'Lon':v['lon'],'Veces':v['count']} for k,v in coords_ent.items()])
                st.dataframe(dfe)
            if use_geo and coords_sal:
                st.markdown('### Coordenadas Salientes (Top)')
                dfs = pd.DataFrame([{'Número':k,'Lat':v['lat'],'Lon':v['lon'],'Veces':v['count']} for k,v in coords_sal.items()])
                st.dataframe(dfs)

            # Mapas interactivos
            if use_geo and (coords_ent or coords_sal):
                import streamlit.components.v1 as components
                st.markdown('---')
                st.markdown('### Mapas interactivos')
                def _show_maps(top_list, coords_dict, role_label=''):
                    for num,_ in top_list:
                        info = coords_dict.get(num)
                        if not info:
                            continue
                        lat, lon = info['lat'], info['lon']
                        html = _gmap_iframe_html(lat, lon, f'{role_label} {num}')
                        components.html(html, height=460)
                _show_maps(top_ent, coords_ent, role_label='Entrante')
                st.markdown('---')
                _show_maps(top_sal, coords_sal, role_label='Saliente')

                # Expander con listado de links (Maps + Street)
                with st.expander('Listado de URLs (Google Maps y Street View)'):
                    st.markdown('**Entrantes**')
                    for num,_ in top_ent:
                        info = coords_ent.get(num)
                        if info:
                            maps = _google_maps_search_url(info['lat'], info['lon'])
                            street = _google_street_url(info['lat'], info['lon'])
                            st.markdown(f'{num}: <a href=\"{maps}\" target=\"_blank\">Maps</a>   |   <a href=\"{street}\" target=\"_blank\">Street</a>', unsafe_allow_html=True)
                    st.markdown('**Salientes**')
                    for num,_ in top_sal:
                        info = coords_sal.get(num)
                        if info:
                            maps = _google_maps_search_url(info['lat'], info['lon'])
                            street = _google_street_url(info['lat'], info['lon'])
                            st.markdown(f'{num}: <a href=\"{maps}\" target=\"_blank\">Maps</a>   |   <a href=\"{street}\" target=\"_blank\">Street</a>', unsafe_allow_html=True)


                # Botón para abrir enlaces en nuevas pestañas desde la propia app (evita depender del visor PDF)
                try:
                    import streamlit.components.v1 as components
                    # Construir lista de enlaces que queremos abrir: Maps y Street de top_ent y top_sal
                    open_links = []
                    for num,_ in top_ent:
                        info = coords_ent.get(num)
                        if info:
                            open_links.append(_google_maps_search_url(info['lat'], info['lon']))
                            open_links.append(_google_street_url(info['lat'], info['lon']))
                    for num,_ in top_sal:
                        info = coords_sal.get(num)
                        if info:
                            open_links.append(_google_maps_search_url(info['lat'], info['lon']))
                            open_links.append(_google_street_url(info['lat'], info['lon']))

                    if open_links:
                        # generar un pequeño HTML/JS con un botón; al hacer clic el JS abrirá cada enlace en pestañas nuevas
                        js = "<html><body><button id=\'openbtn\' style=\'padding:10px 16px;font-size:14px;\'>Abrir todos los enlaces en pestañas nuevas</button><script>document.getElementById(\'openbtn\').onclick = function(){"
                        for link in open_links:
                            js += f"window.open('{link}','_blank');"
                        js += "};</script></body></html>"
                        components.html(js, height=60)
                except Exception:
                    pass

            # Generar PDF y botón de descarga (manteniendo sesión)
            final_pdf = generar_pdf_full(top_ent, top_sal, coords_ent, coords_sal)

            st.download_button('📥 Descargar Reporte en PDF', data=final_pdf.getvalue(), file_name='CEREBRITO2025_release.pdf', mime='application/pdf')


    st.markdown('---')
    st.caption('Diseñado para funcionar sin APIs externas (Google Maps utilizado vía embed y URLs públicas).')


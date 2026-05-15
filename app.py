import streamlit as st
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from datetime import datetime

# Konfigurasi Halaman Streamlit
st.set_page_config(page_title="Verifikator TTE BSrE Pro", page_icon="🛡️", layout="centered")

st.title("🛡️ Verifikator Dokumen TTE Mandiri (Edisi Pro)")
st.write("Unggah dokumen PDF Anda untuk memeriksa validitas kriptografi dan informasi identitas resmi.")

# Komponen Upload File
uploaded_file = st.file_uploader("Pilih file PDF yang sudah ditandatangani", type=["pdf"])

if uploaded_file is not None:
    st.info(f"📂 Memproses file: {uploaded_file.name}")
    
    try:
        # Menggunakan strict=False untuk file format Hybrid-Reference
        reader = PdfFileReader(uploaded_file, strict=False)
        
        if not reader.embedded_signatures:
            st.warning("⚠️ Dokumen tidak mengandung Tanda Tangan Elektronik (TTE) digital.")
        else:
            st.success(f"🔍 Ditemukan {len(reader.embedded_signatures)} tanda tangan digital pada dokumen.")
            
            for idx, sig in enumerate(reader.embedded_signatures):
                st.markdown(f"### Tanda Tangan #{idx + 1}")
                
                # 1. Informasi Dasar Dokumen
                sig_object = sig.sig_object
                signing_time = sig_object.get('/M', 'Tidak Diketahui')
                reason = sig_object.get('/Reason', '-')
                
                # 2. Proses Validasi Kriptografi Lokal & Ekstraksi X.509
                try:
                    status = validate_pdf_signature(sig)
                    is_intact = status.intact
                    cert = status.signing_cert
                    
                    # Parsing Data Subjek (Penandatangan)
                    subject_data = cert.subject.native
                    subject_cn = subject_data.get('common_name', 'Tidak Diketahui')
                    subject_org = subject_data.get('organization_name', '-')
                    subject_ou = subject_data.get('organizational_unit_name', '-')
                    
                    # Ekstraksi NIP / NIK / Nomor Identitas Unik (Kolom Serial Number di Cert)
                    subject_sn = subject_data.get('serial_number', 'Tidak Tercantum di Metadata')
                    
                    # Parsing Data Penerbit (Issuer)
                    issuer_data = cert.issuer.native
                    issuer_cn = issuer_data.get('common_name', 'Tidak Diketahui')
                    
                    # SOLUSI AMAN: Mengambil masa berlaku langsung dari dictionary tbs_certificate internal
                    validity_info = cert.native.get('tbs_certificate', {}).get('validity', {})
                    valid_from_raw = validity_info.get('not_before', 'Tidak Diketahui')
                    valid_until_raw = validity_info.get('not_after', 'Tidak Diketahui')
                    
                    # Konversi tampilan tanggal agar ramah dibaca
                    valid_from = valid_from_raw.strftime('%d-%m-%Y %H:%M:%S') if isinstance(valid_from_raw, datetime) else str(valid_from_raw)
                    valid_until = valid_until_raw.strftime('%d-%m-%Y %H:%M:%S') if isinstance(valid_until_raw, datetime) else str(valid_until_raw)
                    
                    # Cek Masa Berlaku Saat Ini
                    if isinstance(valid_until_raw, datetime):
                        now = datetime.now(valid_until_raw.tzinfo) if valid_until_raw.tzinfo else datetime.now()
                        is_expired = now > valid_until_raw
                    else:
                        is_expired = False
                    
                except Exception as e:
                    is_intact = False
                    is_expired = False
                    subject_cn, subject_org, subject_ou, subject_sn, issuer_cn = "Error", "-", "-", "-", "Error"
                    valid_from, valid_until = "Error", "Error"
                    st.error(f"Gagal memproses metadata sertifikat internal: {str(e)}")

                # 3. Antarmuka Visual Hasil Validasi
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric(label="Integritas Dokumen", value="UTUH (Valid)" if is_intact else "BERUBAH/RUSAK")
                    st.text_input(f"Nama Penandatangan (CN) - #{idx+1}", value=subject_cn, disabled=True)
                    st.text_input(f"NIP / NIK / ID Sertifikat - #{idx+1}", value=str(subject_sn), disabled=True)
                    st.text_input(f"Mulai Berlaku - #{idx+1}", value=valid_from, disabled=True)
                    st.text_input(f"Waktu Penandatanganan (Kamus PDF) - #{idx+1}", value=str(signing_time), disabled=True)

                with col2:
                    is_bsre = "bsre" in issuer_cn.lower() or "balai sertifikasi elektronik" in issuer_cn.lower() or "bssn" in issuer_cn.lower()
                    st.metric(label="Otoritas Sertifikat (CA)", value="BSrE / BSSN" if is_bsre else "CA Eksternal/Lain")
                    st.text_input(f"Instansi / Organisasi - #{idx+1}", value=str(subject_org), disabled=True)
                    st.text_input(f"Unit Kerja (OU) - #{idx+1}", value=str(subject_ou), disabled=True)
                    
                    # Indikator status kedaluwarsa sertifikat
                    st.text_input(f"Masa Berlaku Sertifikat - #{idx+1}", value=valid_until, disabled=True)
                    st.text_input(f"Alasan Penandatanganan - #{idx+1}", value=reason, disabled=True)

                # Kesimpulan Akhir Status Keaslian Komprehensif
                if is_intact and is_bsre and not is_expired:
                    st.success(f"✅ Tanda Tangan #{idx+1} SAH, menggunakan Sertifikat AKTIF resmi dari BSrE BSSN.")
                elif is_intact and is_bsre and is_expired:
                    st.warning(f"⚠️ Tanda Tangan #{idx+1} Kriptografi UTUH dari BSrE, namun Masa Berlaku Sertifikat saat ini sudah KEDALUWARSA.")
                elif is_intact and not is_bsre:
                    st.warning(f"⚠️ Tanda Tangan #{idx+1} Kriptografi UTUH, namun diterbitkan oleh CA luar (Bukan BSrE BSSN).")
                else:
                    st.error(f"❌ Tanda Tangan #{idx+1} TIDAK VALID. Berkas terdeteksi telah mengalami modifikasi!")
                
                st.markdown("---")
                
    except Exception as e:
        st.error(f"Terjadi kesalahan mendasar saat membaca file PDF: {str(e)}")

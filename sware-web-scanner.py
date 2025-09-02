# telegram: @spyizxa_0day
_Ae='Access-Control-Allow-Origin'
_Ad='Feature-Policy'
_Ac='Permissions-Policy'
_Ab='wp-config.php'
_Aa='backup.zip'
_AZ='server-status'
_AY='robots.txt'
_AX='..%2f..%2fwindows%2fwin.ini'
_AW='../../windows/win.ini'
_AV='..%2f..%2fetc%2fpasswd'
_AU='../../etc/passwd'
_AT='Recon Only'
_AS='Sadece Recon'
_AR='normal'
_AQ='%Y-%m-%d %H:%M:%S'
_AP='Open Redirect'
_AO='expiringSoon'
_AN='final'
_AM='admin'
_AL='TRACE'
_AK='DELETE'
_AJ='OWASP Top 10'
_AI='Hızlı'
_AH='clicked_ai'
_AG='ai_summary_title'
_AF='save_failed'
_AE='saved'
_AD='pdf_missing'
_AC='save_err_url'
_AB='find_total'
_AA='risk_total'
_A9='profile_lbl'
_A8='started'
_A7='profile_owasp'
_A6='profile_recon'
_A5='profile_full'
_A4='profile_bal'
_A3='profile_fast'
_A2='ai_done'
_A1='clear'
_A0='medium'
_z='high'
_y='critical'
_x='filter'
_w='progress'
_v='disabled'
_u='raw'
_t='issuer'
_s='subject'
_r='CRITICAL'
_q='https://'
_p='redirect'
_o='ai_analyze'
_n='console'
_m='stop'
_l='scan'
_k='threads'
_j='target_url'
_i='scan_profile'
_h='notAfter'
_g='all'
_f='payload'
_e='status'
_d='headers'
_c='results'
_b='pdf'
_a=':'
_Z='path'
_Y='severity'
_X='json'
_W='txt'
_V=False
_U='title'
_T='HIGH'
_S='info'
_R='type'
_Q='bad'
_P='MEDIUM'
_O='ok'
_N='GET'
_M='LOW'
_L='tr'
_K='finding'
_J=True
_I='warn'
_H='kv'
_G='error'
_F='url'
_E=None
_D='findings'
_C='tag'
_B='step'
_A='msg'
import tkinter as tk
from tkinter import filedialog,messagebox,ttk
from tkinter.scrolledtext import ScrolledText
import threading,queue,json,time,ssl,socket,subprocess,re,random,os
from urllib.parse import urljoin,urlparse,parse_qsl,urlencode,quote
import requests
from datetime import datetime,timedelta
try:from bs4 import BeautifulSoup;HAS_BS4=_J
except Exception:HAS_BS4=_V
try:import whois as pywhois;HAS_PYWHOIS=_J
except Exception:HAS_PYWHOIS=_V
try:from reportlab.lib.pagesizes import A4;from reportlab.pdfgen import canvas;HAS_PDF=_J
except Exception:HAS_PDF=_V
APP_TITLE='⚡ SwareCommunity - WeB scanner'
UA={'User-Agent':'Mozilla/5.0 (compatible; SWARE-Scanner/3.0)'}
TIMEOUT=8
I18N={_L:{_i:'Tarama Profili',_j:'Hedef URL',_k:'Thread Sayısı',_l:'🚀 Tara',_m:'⛔ Durdur',_W:'💾 TXT',_X:'💾 JSON',_b:'📄 PDF',_n:'Konsol',_c:'Sonuçlar',_x:'Filtre',_g:'Tümü',_y:'Kritik',_z:'Yüksek',_A0:'Orta','low':'Düşük',_A1:'Temizle','lang':'Dil',_o:'🧠 AI Analizi',_A2:'AI analizi tamamlandı.',_A3:_AI,_A4:'Orta',_A5:'Tam',_A6:_AS,_A7:_AJ,_A8:'Tarama başladı',_A9:'Profil',_AA:'Toplam risk skoru',_AB:'Bulgu sayısı',_AC:'Geçerli bir URL girin.',_AD:'reportlab yüklü değil.',_AE:'Kaydedildi',_AF:'Kaydedilemedi',_AG:'AI Özet/Önceliklendirme',_AH:'AI analiz isteniyor...'},'en':{_i:'Scan Profile',_j:'Target URL',_k:'Threads',_l:'🚀 Scan',_m:'⛔ Stop',_W:'💾 TXT',_X:'💾 JSON',_b:'📄 PDF',_n:'Console',_c:'Results',_x:'Filter',_g:'All',_y:'Critical',_z:'High',_A0:'Medium','low':'Low',_A1:'Clear','lang':'Lang',_o:'🧠 AI Analyze',_A2:'AI analysis completed.',_A3:'Fast',_A4:'Balanced',_A5:'Full',_A6:_AT,_A7:_AJ,_A8:'Scan started',_A9:'Profile',_AA:'Total risk score',_AB:'Total findings',_AC:'Enter a valid URL.',_AD:'reportlab not installed.',_AE:'Saved',_AF:'Save failed',_AG:'AI Summary/Prioritization',_AH:'Running AI-style analysis...'}}
def t(key,lang=_L):return I18N.get(lang,I18N[_L]).get(key,key)
XSS_PAYLOADS=["<script>alert('XSS')</script>",'"><img src=x onerror=alert(1)>','javascript:alert(1)','onmouseover=alert(1)']
SQLI_PAYLOADS=["'",'"',"' OR '1'='1",'" OR "1"="1',"'--","') OR ('1'='1","admin'--","' UNION SELECT NULL--","' OR 1=1--"]
LFI_PAYLOADS=[_AU,_AV,_AW,_AX]
SSTI_PAYLOADS=['{{7*7}}','<%= 7*7 %>','${7*7}']
REDIRECT_PARAMS=['next',_F,'target','r','return',_p,'goto','destination']
COMMON_METHODS=[_N,'POST','HEAD','OPTIONS','PUT',_AK,_AL,'PATCH']
SENSITIVE_PATHS=[_AY,'.env','.git/','phpinfo.php',_AZ,_Aa,'db.sql','config.php.bak','.DS_Store','.svn/','_admin/','admin/','login/','uploads/','backup/','old/',_Ab,'web.config']
ADMIN_PANEL_PATHS=[_AM,'administrator','wp-admin','panel','dashboard','control','manager','login','admin/login','adminpanel','user/login','admincp','admin_area','admin/login.php','admin/index.php','admin/admin.php','admin/account.php','admin/admin_login.php','admin/controlpanel.php','cp','administrator/login']
SUBD_BRUTE=['www','mail','api','dev','test','stage','staging',_AM,'portal','cp','cdn','img','static','ftp','webmail']
DIR_BRUTE=['admin/','administrator/','login/','dashboard/','backup/','old/','test/','dev/','staging/','config/','uploads/','includes/','vendor/','api/',_AZ,'wp-admin/','wp-content/','wp-includes/']
TOP_PORTS=[21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5632,5900,6379,7001,7002,8000,8080,8081,8443,9000,9200,9300,11211,27017]
def normalize_url(raw):
	A=raw;A=(A or'').strip()
	if not A:return
	if not A.startswith(('http://',_q)):A=_q+A
	return A
def base_host(url):return urlparse(url).hostname or url
def safe_req(method,url,**A):
	G='params';F='data';E='allow_redirects';D='timeout';B=method
	try:
		C=A.pop('session',_E)
		if C:return C.request(B,url,headers=UA,timeout=A.get(D,TIMEOUT),allow_redirects=A.get(E,_J),verify=_J,data=A.get(F),params=A.get(G))
		else:return requests.request(B,url,headers=UA,timeout=A.get(D,TIMEOUT),allow_redirects=A.get(E,_J),verify=_J,data=A.get(F),params=A.get(G))
	except Exception as H:return H
def run_whois_cli(domain):
	try:
		A=subprocess.run(['whois',domain],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=_J,timeout=20)
		if A.returncode==0 and A.stdout.strip():return A.stdout
	except Exception:pass
SEVERITY_WEIGHTS={_M:1,_P:3,_T:6,_r:10}
def make_finding(title,severity=_M,detail=_E,url=_E):return{_U:title,_Y:severity,'detail':detail,_F:url}
def total_risk(findings):return sum(SEVERITY_WEIGHTS.get(A[_Y],0)for A in findings)
def http_to_https_redirect(base_url):
	B=urlparse(base_url)._replace(scheme='http').geturl();A=safe_req(_N,B)
	if isinstance(A,Exception):return{_G:str(A),_AN:_E,_p:_E}
	return{_G:_E,_AN:A.url,_p:A.url.startswith(_q)}
def https_presence(base_url):return base_url.startswith(_q)
def ssl_info(base_url):
	D='commonName';A={_s:_E,_t:_E,_h:_E,_G:_E,_AO:_V}
	try:
		C=base_host(base_url);E=ssl.create_default_context()
		with socket.create_connection((C,443),timeout=TIMEOUT)as F:
			with E.wrap_socket(F,server_hostname=C)as G:B=G.getpeercert()
		H=dict(B for A in B.get(_s,[])for B in A).get(D);I=dict(B for A in B.get(_t,[])for B in A).get(D);A[_s]=H;A[_t]=I;A[_h]=B.get(_h)
		try:J=datetime.strptime(B.get(_h),'%b %d %H:%M:%S %Y %Z');A[_AO]=J<datetime.utcnow()+timedelta(days=30)
		except Exception:pass
	except Exception as K:A[_G]=str(K)
	return A
def dns_lookup(base_url):
	B=base_host(base_url);A={'A':[],_G:_E}
	try:C=socket.getaddrinfo(B,_E,family=socket.AF_INET);A['A']=sorted({A[4][0]for A in C})
	except Exception as D:A[_G]=str(D)
	return A
def whois_info(base_url):
	A='source';B=base_host(base_url)
	if HAS_PYWHOIS:
		try:D=pywhois.whois(B);return{A:'python-whois',_u:str(D)}
		except Exception:pass
	C=run_whois_cli(B)
	if C:return{A:'whois-cli',_u:C}
	return{A:_E,_u:_E,_G:'WHOIS alınamadı / WHOIS failed.'}
def headers_and_security(base_url,session=_E):
	A=safe_req(_N,base_url,session=session)
	if isinstance(A,Exception):return{_G:str(A),_d:{}}
	B=A.headers;return{_G:_E,_d:dict(B),'text':A.text,_e:A.status_code}
def xss_quick(base_url,session=_E):
	D=session;A=base_url;B=[];E=safe_req(_N,A,session=D)
	if isinstance(E,Exception):return{_D:B,_G:str(E)}
	for C in XSS_PAYLOADS[:2]:
		F=safe_req(_N,A,params={'q':C},session=D)
		if not isinstance(F,Exception)and C in F.text:B.append({_F:A,_R:'Reflected XSS',_f:C})
	return{_D:B,_G:_E}
def mutate_params(url,key,val):A=urlparse(url);B=dict(parse_qsl(A.query,keep_blank_values=_J));B[key]=val;C=A._replace(query=urlencode(B,doseq=_J)).geturl();return C
def sqli_test(base_url,session=_E):
	A=base_url;B=[];F=urlparse(A);G=dict(parse_qsl(F.query))
	for H in G.keys():
		for C in SQLI_PAYLOADS:
			D=mutate_params(A,H,C);E=safe_req(_N,D,session=session)
			if isinstance(E,Exception):continue
			if re.search('(SQL syntax|mysql_fetch|ORA-|SQLite|psql:|unterminated|warning.*mysql)',E.text,re.I):B.append({_F:D,_R:'SQLi error-based',_f:C});break
	return{_D:B}
def lfi_test(base_url,session=_E):
	B=base_url;C=[];F=urlparse(B);G=dict(parse_qsl(F.query));H=[A for A in G.keys()or['file',_Z,'page','include','template']]
	for I in H:
		for D in[_AU,_AV,_AW,_AX]:
			E=mutate_params(B,I,D);A=safe_req(_N,E,session=session)
			if isinstance(A,Exception):continue
			if'root:x:0:0:'in A.text or'[extensions]'in A.text:C.append({_F:E,_R:'LFI',_f:D});break
	return{_D:C,_G:_E}
def open_redirect_test(base_url,session=_E):
	B=[]
	for D in REDIRECT_PARAMS:
		C=mutate_params(base_url,D,'http://example.com');A=safe_req(_N,C,allow_redirects=_V,session=session)
		if isinstance(A,Exception):continue
		if A.status_code in(301,302,307,308)and'example.com'in A.headers.get('Location',''):B.append({_F:C,_R:_AP})
	return{_D:B}
def check_clickjacking(headers):
	C='X-Frame-Options';A=headers;B=A.get(C,'')or A.get(C.lower(),'')
	if not B or B.lower()not in('deny','sameorigin'):return make_finding('Clickjacking koruması yok / X-Frame-Options missing',_T)
def check_xcto(headers):
	A=headers.get('X-Content-Type-Options','')
	if A.lower()!='nosniff':return make_finding('X-Content-Type-Options eksik/yanlış',_P)
def check_referrer_policy(headers):
	A=headers.get('Referrer-Policy','')
	if not A:return make_finding('Referrer-Policy eksik',_M)
	B={'unsafe-url','no-referrer-when-downgrade'}
	if any(B in A.lower()for B in B):return make_finding('Referrer-Policy zayıf',_M)
def check_permissions_policy(headers):
	A=headers;B=A.get(_Ac,'')or A.get(_Ad,'')
	if not B:return make_finding('Permissions-Policy/Feature-Policy eksik',_M)
def check_cache_control(headers,status):
	A=headers;B=A.get('Cache-Control','')+' '+A.get('Pragma','')
	if status==200 and not any(A in B.lower()for A in['no-store','no-cache','private']):return make_finding('Cache-Control zayıf (no-store yok)',_M)
def check_cors(headers):
	A=headers;B=A.get(_Ae,'');C=A.get('Access-Control-Allow-Credentials','')
	if B=='*'and C.lower()=='true':return make_finding('CORS yanlış yapılandırma (* + credentials)',_T)
	if B=='*':return make_finding('CORS tüm originlere açık (*)',_P)
def check_trace_options(base_url,session=_E):
	D=session;A=base_url;B=[];C=safe_req(_AL,A,allow_redirects=_V,session=D)
	if not isinstance(C,Exception)and C.status_code in(200,405):
		if C.status_code==200:B.append(make_finding('TRACE metodu etkin',_P,url=A))
	E=safe_req('OPTIONS',A,allow_redirects=_V,session=D)
	if not isinstance(E,Exception):
		F=E.headers.get('Allow','')
		if any(A in F for A in['PUT',_AK,_AL]):B.append(make_finding('Gereksiz/tehlikeli HTTP metodları açık',_P,F,A))
	return B
def rate_limit_probe(base_url,n=10,session=_E):
	A=[];C=time.perf_counter()
	for F in range(n):
		B=safe_req(_N,base_url,params={'_rl':random.randint(1,1000000)},session=session)
		if isinstance(B,Exception):continue
		A.append(B.status_code);time.sleep(.05)
	D=time.perf_counter()-C;E=A.count(429)>=1;return{'requests':n,'duration_sec':round(D,2),'codes':A,'flagged':E}
def ssti_test(base_url,session=_E):
	B=[]
	for C in SSTI_PAYLOADS:
		A=safe_req(_N,base_url,params={'name':C},session=session)
		if isinstance(A,Exception):continue
		if'49'in A.text or'34359738368'in A.text:B.append({_F:A.url,_R:'SSTI',_f:C});break
	return{_D:B}
def idor_quick(base_url,session=_E):
	A=base_url;B=[];H=urlparse(A);I=dict(parse_qsl(H.query))
	for(F,C)in list(I.items()):
		if C.isdigit():
			J=[str(max(0,int(C)-1)),str(int(C)+1)]
			for G in J:
				D=mutate_params(A,F,G);E=safe_req(_N,D,session=session)
				if isinstance(E,Exception):continue
				if E.status_code==200 and len(E.text)>0 and D!=A:B.append({_F:D,_R:'IDOR?',_f:f"{F}={G}"});return{_D:B}
	return{_D:B}
def sensitive_paths_scan(base_url,session=_E):
	B=[]
	for C in SENSITIVE_PATHS:
		D=urljoin(base_url,C);A=safe_req(_N,D,session=session)
		if isinstance(A,Exception):continue
		if A.status_code in(200,301,302,307,308,401,403):B.append({_Z:C,_e:A.status_code,_F:D})
	return B
def robots_analyze(base_url,session=_E):
	C=base_url;F=urljoin(C,_AY);A=safe_req(_N,F,session=session)
	if isinstance(A,Exception)or A.status_code!=200:return[]
	G=[_AM,'backup','private','secret','.git','temp','staging'];D=[]
	for E in A.text.splitlines():
		if E.lower().startswith('disallow:'):
			B=E.split(_a)[1].strip()
			if any(A in B.lower()for A in G):D.append(make_finding('robots.txt hassas dizin',_M,B,urljoin(C,B.lstrip('/'))))
	return D
def stacktrace_leak(text,url):
	if re.search('(Traceback|Exception in thread|Stack trace|NullPointerException|Fatal error:)',text,re.I):return make_finding('Stack trace/sunucu hatası açığa çıkması',_P,url=url)
def default_page_detect(text):
	A=['It works!','Welcome to nginx!','Index of /']
	if any(A.lower()in text.lower()for A in A):return make_finding('Varsayılan sunucu sayfası',_M)
def cors_preflight_test(base_url,session=_E):
	A=base_url
	try:
		B=session.options(A,headers={'Origin':'https://evil.test','Access-Control-Request-Method':_N})
		if B.status_code in(200,204):
			C=B.headers.get(_Ae,'')
			if C=='*'or'evil.test'in C:return make_finding('CORS Preflight gevşek',_P,url=A)
	except Exception:pass
def permissions_header_loose(headers):
	B=headers;A=B.get(_Ac,'')or B.get(_Ad,'')
	if A and('geolocation=*'in A or'camera=*'in A):return make_finding('Permissions-Policy çok geniş',_M)
def hsts_check(headers):
	A=headers.get('Strict-Transport-Security')
	if not A:return make_finding('HSTS yok',_P)
	B=re.search('max-age=(\\d+)',A or'',re.I)
	if not B or int(B.group(1))<15552000:return make_finding('HSTS zayıf (max-age düşük)',_M)
def cookies_flags(headers):
	C=headers.get('Set-Cookie','');D=[]
	if C:
		E=C.split(',')
		for F in E:
			B=F.lower();A=[]
			if'secure'not in B:A.append('Secure')
			if'httponly'not in B:A.append('HttpOnly')
			if'samesite'not in B:A.append('SameSite')
			if A:D.append(make_finding('Zayıf cookie bayrakları',_P,', '.join(A)))
	return D
def methods_put_delete_test(base_url,session=_E):
	B=base_url;C=[]
	for D in['PUT',_AK]:
		A=safe_req(D,B,allow_redirects=_V,session=session)
		if not isinstance(A,Exception)and A.status_code in(200,201,202,204,401,403):E=_T if A.status_code in(200,201,202,204)else _M;C.append(make_finding(f"{D} metodu etkin",E,url=B))
	return C
def weak_csp(headers):
	A=headers.get('Content-Security-Policy','')
	if not A:return make_finding('CSP yok',_T)
	if'unsafe-inline'in A or'*'in A:return make_finding('CSP zayıf (unsafe-inline/*)',_P)
def content_type_mismatch(headers,text):
	A=headers.get('Content-Type','')
	if'text/html'in A.lower()and text.strip().startswith('{'):return make_finding('Content-Type uyumsuz (HTML yerine JSON?)',_M)
def service_banner_leak(headers):
	B=headers;A=B.get('Server','')+' '+B.get('X-Powered-By','')
	if A and any(B in A.lower()for B in['apache','nginx','iis','php','express','asp.net']):return make_finding('Sunucu/teknoloji banner sızıntısı',_M,A.strip())
def port_scan_top(host,ports=TOP_PORTS,timeout=.5):
	A=[]
	for B in ports:
		try:
			with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as C:
				C.settimeout(timeout)
				if C.connect_ex((host,B))==0:A.append(B)
		except Exception:pass
	return A
class App:
	def __init__(A,root):
		c='URL';b='Title';a='#0b0f17';Z='white';Y='#ff5566';X='#00ffa3';W='<<ComboboxSelected>>';T='#7aa2f7';S='readonly';M='right';L='bold';K='both';I='black';H='x';F='left';D='#9aa7bd';C='Consolas';B='#2b2b2b';A.root=root;A.lang=tk.StringVar(value=_L);A.root.title(APP_TITLE);A.root.configure(bg=B);A.q=queue.Queue();A.stop_flag=threading.Event();A.results={'app':APP_TITLE,'time':time.strftime(_AQ),_c:{},_D:[]};A.session=requests.Session();E=tk.Frame(root,bg=B);E.pack(fill=K,expand=_J,padx=10,pady=10);N=tk.Frame(E,bg=B);N.pack(fill=H,pady=(0,6));tk.Label(N,text='🌐 '+t('lang',A.lang.get()),font=(C,10),fg=D,bg=B).pack(side=F);A.lang_combo=ttk.Combobox(N,textvariable=A.lang,values=[_L,'en'],state=S,width=5);A.lang_combo.pack(side=F,padx=6);A.lang_combo.bind(W,A.refresh_labels);d=tk.Label(E,text=APP_TITLE,font=(C,16,L),fg=T,bg=B);d.pack(pady=(0,8));O=tk.Frame(E,bg=B);O.pack(fill=H,pady=5);A.profile_var=tk.StringVar(value=_AI);A.profile_combo=ttk.Combobox(O,textvariable=A.profile_var,values=[t(_A3,_L),t(_A4,_L),t(_A5,_L),t(_A6,_L),t(_A7,_L)],state=S,width=18);A.profile_combo.pack(side=M);A.profile_label=tk.Label(O,text=t(_i,A.lang.get())+_a,font=(C,11),fg=D,bg=B);A.profile_label.pack(side=M,padx=(0,8));P=tk.Frame(E,bg=B);P.pack(fill=H,pady=5);A.target_label=tk.Label(P,text=t(_j,A.lang.get())+_a,font=(C,11),fg=D,bg=B);A.target_label.pack(side=F,padx=(0,8));A.entry=tk.Entry(P,width=60,font=(C,10));A.entry.pack(side=F,fill=H,expand=_J);Q=tk.Frame(E,bg=B);Q.pack(fill=H,pady=5);A.thread_label=tk.Label(Q,text=t(_k,A.lang.get())+_a,font=(C,11),fg=D,bg=B);A.thread_label.pack(side=F,padx=(0,8));A.thread_var=tk.IntVar(value=5);A.thread_spin=tk.Spinbox(Q,from_=1,to=20,textvariable=A.thread_var,width=5,font=(C,10));A.thread_spin.pack(side=F);G=tk.Frame(E,bg=B);G.pack(pady=8);A.btn_go=tk.Button(G,text=t(_l,A.lang.get()),command=A.start,bg=X,fg=I,font=(C,10,L));A.btn_go.grid(row=0,column=0,padx=5);A.btn_stop=tk.Button(G,text=t(_m,A.lang.get()),command=A.stop,state=_v,bg=Y,fg=Z,font=(C,10,L));A.btn_stop.grid(row=0,column=1,padx=5);A.btn_ai=tk.Button(G,text=t(_o,A.lang.get()),command=A.run_ai,bg=T,fg=I,font=(C,10,L));A.btn_ai.grid(row=0,column=2,padx=5);A.btn_txt=tk.Button(G,text=t(_W,A.lang.get()),command=lambda:A.save(_W),bg=D,fg=I,font=(C,10));A.btn_txt.grid(row=0,column=3,padx=5);A.btn_json=tk.Button(G,text=t(_X,A.lang.get()),command=lambda:A.save(_X),bg=D,fg=I,font=(C,10));A.btn_json.grid(row=0,column=4,padx=5);A.btn_pdf=tk.Button(G,text=t(_b,A.lang.get()),command=lambda:A.save(_b),bg=D,fg=I,font=(C,10));A.btn_pdf.grid(row=0,column=5,padx=5)
		if not HAS_PDF:A.btn_pdf.config(state=_v)
		A.prog=ttk.Progressbar(E,mode='determinate',maximum=1,value=0);A.prog.pack(fill=H,pady=(0,6));A.notebook=ttk.Notebook(E);A.notebook.pack(fill=K,expand=_J);A.console_frame=tk.Frame(A.notebook,bg=a);A.notebook.add(A.console_frame,text=t(_n,A.lang.get()));A.console=ScrolledText(A.console_frame,width=110,height=28,bg=a,fg='#b8e1ff',insertbackground=Z,font=(C,10),bd=0);A.console.pack(fill=K,expand=_J);A.results_frame=tk.Frame(A.notebook,bg=B);A.notebook.add(A.results_frame,text=t(_c,A.lang.get()));U='Severity',b,c;A.results_tree=ttk.Treeview(A.results_frame,columns=U,show='headings',height=20)
		for R in U:A.results_tree.heading(R,text=R);A.results_tree.column(R,width=100)
		A.results_tree.column(b,width=300);A.results_tree.column(c,width=380);V=ttk.Scrollbar(A.results_frame,orient='vertical',command=A.results_tree.yview);A.results_tree.configure(yscrollcommand=V.set);A.results_tree.pack(side=F,fill=K,expand=_J);V.pack(side=M,fill='y');J=tk.Frame(A.results_frame,bg=B);J.pack(fill=H,pady=5);tk.Label(J,text=t(_x,A.lang.get())+_a,fg=D,bg=B).pack(side=F,padx=5);A.filter_var=tk.StringVar();A.filter_combo=ttk.Combobox(J,textvariable=A.filter_var,values=[t(_g,_L),t(_y,_L),t(_z,_L),t(_A0,_L),t('low',_L)],state=S,width=12);A.filter_combo.set(t(_g,_L));A.filter_combo.pack(side=F,padx=5);A.filter_combo.bind(W,A.filter_results);tk.Button(J,text=t(_A1,A.lang.get()),command=A.clear_results,bg=D,fg=I).pack(side=M,padx=5)
		for(e,f)in{_O:X,_I:'#ffd166',_Q:Y,_S:D,_U:T}.items():A.console.tag_config(e,foreground=f)
	def refresh_labels(A,event=_E):A.btn_go.config(text=t(_l,A.lang.get()));A.btn_stop.config(text=t(_m,A.lang.get()));A.btn_txt.config(text=t(_W,A.lang.get()));A.btn_json.config(text=t(_X,A.lang.get()));A.btn_pdf.config(text=t(_b,A.lang.get()));A.btn_ai.config(text=t(_o,A.lang.get()));A.notebook.tab(0,text=t(_n,A.lang.get()));A.notebook.tab(1,text=t(_c,A.lang.get()));A.profile_label.config(text=t(_i,A.lang.get())+_a);A.target_label.config(text=t(_j,A.lang.get())+_a);A.thread_label.config(text=t(_k,A.lang.get())+_a)
	def log(A,msg,tag=_S):A.console.insert(tk.END,msg+'\n',tag);A.console.see(tk.END)
	def add_res(A,key,val):A.results[_c][key]=val
	def add_find(B,finding):A=finding;B.results[_D].append(A);B.results_tree.insert('','end',values=(A[_Y],A[_U],A.get(_F,'')))
	def filter_results(A,event=_E):
		C=A.filter_var.get().lower()
		for D in A.results_tree.get_children():A.results_tree.delete(D)
		for B in A.results[_D]:
			E=B[_Y].lower()
			if C in('tümü',_g)or C==E:A.results_tree.insert('','end',values=(B[_Y],B[_U],B.get(_F,'')))
	def clear_results(A):
		for B in A.results_tree.get_children():A.results_tree.delete(B)
	def start(A):
		B=normalize_url(A.entry.get())
		if not B:messagebox.showerror('Hata',t(_AC,A.lang.get()));return
		A.console.delete('1.0',tk.END);A.results={'app':APP_TITLE,'time':time.strftime(_AQ),_c:{},_D:[]};A.clear_results();A.stop_flag.clear();A.btn_go.config(state=_v);A.btn_stop.config(state=_AR);C=A.profile_var.get();D=A.get_steps_count(C);A.prog.configure(value=0,maximum=D);A.log(f"== {t(_A8,A.lang.get())}: {B} ==",_U);A.log(f"== {t(_A9,A.lang.get())}: {C} ==",_S);threading.Thread(target=A.worker,args=(B,C),daemon=_J).start();A.root.after(100,A.pump)
	def get_steps_count(A,profile):return len(A.get_steps_for_profile('','','',profile))
	def stop(A):A.stop_flag.set();A.log('Stop requested / Durdurma istendi...',_I)
	def pump(A):
		try:
			while _J:
				C,B=A.q.get_nowait()
				if C==_B:
					if B.get(_A):A.log(B[_A],B.get(_C,_S))
					if _H in B:A.add_res(B[_H][0],B[_H][1])
					if _K in B:A.add_find(B[_K])
					if _D in B:
						for D in B[_D]:A.add_find(D)
					if _w in B:A.prog.configure(value=B[_w])
				elif C=='done':E=total_risk(A.results[_D]);A.log(f"\n[=] {t(_AA,A.lang.get())}: {E}",_U);A.log(f"[=] {t(_AB,A.lang.get())}: {len(A.results[_D])}",_S);A.btn_go.config(state=_AR);A.btn_stop.config(state=_v);A.notebook.select(1)
		except queue.Empty:pass
		if A.btn_stop['state']==_AR:A.root.after(120,A.pump)
	def worker(A,base,profile):
		B=base_host(base);F=B;C=A.get_steps_for_profile(base,B,F,profile);I=len(C)
		for(D,(E,G))in enumerate(C,start=1):
			if A.stop_flag.is_set():break
			try:G()
			except Exception as H:A.q.put((_B,{_A:f"[!] {E} error: {H}",_C:_Q,_w:D}))
			else:A.q.put((_B,{_A:f"[•] {E} ok.",_C:_S,_w:D}))
		A.q.put(('done',{}))
	def get_steps_for_profile(A,base,host,domain,profile):
		D=profile;B=base;C=[('HTTP→HTTPS',lambda:A.step_redirect(B)),('HTTPS presence',lambda:A.step_https(B)),('Headers grab',lambda:A.step_headers(B)),('SSL',lambda:A.step_ssl(B)),('DNS',lambda:A.step_dns(B)),('WHOIS',lambda:A.step_whois(B)),('Extra Header Sec',lambda:A.step_extra_header_sec(B)),('CORS',lambda:A.step_cors(B)),('TRACE/OPTIONS',lambda:A.step_trace_opts(B))];F=[('Sensitive paths',lambda:A.step_sensitive(B)),('Robots',lambda:A.step_robots(B)),('Dir brute',lambda:A.step_directories(B)),('Port scan',lambda:A.step_ports(host))];E=[('XSS',lambda:A.step_xss(B)),('SQLi',lambda:A.step_sqli(B)),('LFI',lambda:A.step_lfi(B)),(_AP,lambda:A.step_redirect_open(B)),('SSTI',lambda:A.step_ssti(B)),('IDOR quick',lambda:A.step_idor(B)),('Rate limit',lambda:A.step_rate_limit(B))]
		if D in(_AI,'Fast'):return C+E[:3]
		elif D in('Orta','Balanced'):return C+F[:2]+E
		elif D in('Tam','Full'):return C+F+E
		elif D in(_AS,_AT):return C[:5]+F
		elif D in(_AJ,):return C+E
		else:return C+E
	def step_redirect(B,base):
		C='http_redirect';A=http_to_https_redirect(base)
		if A[_G]is not _E:B.q.put((_B,{_A:f"[?] HTTP→HTTPS failed: {A[_G]}",_C:_I,_H:(C,A)}));return
		if not A[_p]:B.q.put((_B,{_A:'[!] No HTTP→HTTPS redirect!',_C:_Q,_K:make_finding('HTTP→HTTPS yok',_P,url=base)}))
		B.q.put((_B,{_A:f"[HTTP→HTTPS] final: {A[_AN]}",_C:_O,_H:(C,A)}))
	def step_https(A,base):
		B=https_presence(base)
		if not B:A.q.put((_B,{_A:'[HTTPS] not used!',_C:_Q,_K:make_finding('HTTPS yok',_T,url=base)}))
		else:A.q.put((_B,{_A:'[HTTPS] OK',_C:_O}))
		A.q.put((_B,{_H:('https',B),_A:''}))
	def step_headers(A,base):
		B=headers_and_security(base,A.session)
		if B[_G]:A.q.put((_B,{_A:f"[Header] failed: {B[_G]}",_C:_I,_H:(_d,{})}));return
		D=B.get('text','');C=B.get(_d,{});I=B.get(_e,0)
		if C:
			for E in cookies_flags(C):A.q.put((_B,{_A:f"[Cookie] {E["detail"]}",_C:_I,_K:E}))
			F=stacktrace_leak(D,base)
			if F:A.q.put((_B,{_A:'[Stacktrace] leak detected',_C:_Q,_K:F}))
			G=default_page_detect(D)
			if G:A.q.put((_B,{_A:'[Default] server page',_C:_I,_K:G}))
			H=content_type_mismatch(C,D)
			if H:A.q.put((_B,{_A:'[CT] mismatch',_C:_I,_K:H}))
		A.q.put((_B,{_A:'[Header] captured.',_H:(_d,C)}))
	def step_ssl(B,base):
		A=ssl_info(base)
		if A.get(_G):B.q.put((_B,{_A:f"[SSL] failed: {A[_G]}",_C:_I}))
		else:
			C=f"[SSL] Subject:{A.get(_s)} Issuer:{A.get(_t)} Expires:{A.get(_h)}"
			if A.get(_AO):C+=' (expiring soon)'
			B.q.put((_B,{_A:C,_C:_O}))
		B.q.put((_B,{_H:('ssl',A),_A:''}))
	def step_dns(B,base):
		A=dns_lookup(base)
		if A.get(_G):B.q.put((_B,{_A:f"[DNS] error: {A[_G]}",_C:_I}))
		else:B.q.put((_B,{_A:f"[DNS] A: {", ".join(A["A"])or"-"}",_C:_O}))
		B.q.put((_B,{_H:('dns',A),_A:''}))
	def step_whois(B,base):A=whois_info(base);C='[WHOIS] info fetched.'if A.get(_u)else f"[WHOIS] failed. {A.get(_G,"")}";B.q.put((_B,{_A:C,_C:_S}));B.q.put((_B,{_H:('whois',A),_A:''}))
	def step_extra_header_sec(D,base):
		B=headers_and_security(base,D.session)
		if B[_G]:return
		A=B[_d];E=B.get(_e,0);G=B.get('text','');F=[check_clickjacking(A),check_xcto(A),check_referrer_policy(A),check_permissions_policy(A),check_cache_control(A,E),weak_csp(A),hsts_check(A),permissions_header_loose(A),service_banner_leak(A)]
		for C in F:
			if C:D.q.put((_B,{_A:f"[HeaderSec] {C[_U]}",_C:_I,_K:C}))
	def step_cors(B,base):
		C=headers_and_security(base,B.session)
		if C[_G]:return
		A=[];D=check_cors(C[_d])
		if D:A.append(D)
		E=cors_preflight_test(base,B.session)
		if E:A.append(E)
		if A:B.q.put((_B,{_A:'[CORS] misconfig detected',_C:_Q,_D:A}))
		B.q.put((_B,{_H:('cors',{_D:[A[_U]for A in A]}),_A:''}))
	def step_trace_opts(A,base):
		B=check_trace_options(base,A.session)
		if B:A.q.put((_B,{_A:'[HTTP Methods] issues',_C:_I,_D:B}))
		C=methods_put_delete_test(base,A.session)
		if C:A.q.put((_B,{_A:'[HTTP Methods] PUT/DELETE',_C:_I,_D:C}))
	def step_sensitive(B,base):
		C=sensitive_paths_scan(base,B.session)
		if C:
			B.q.put((_B,{_A:f"[Sensitive] {len(C)} clues",_C:_I}))
			for A in C[:5]:B.q.put((_B,{_A:f"[Sensitive] {A[_Z]} -> {A[_e]}",_C:_S}))
			for A in C:D=_T if A[_Z]in('.env','.git/','db.sql',_Aa,_Ab)else _M;B.add_find(make_finding('Hassas/ilginç yol',D,A[_Z],A[_F]))
		B.q.put((_B,{_H:('sensitive_paths',C),_A:''}))
	def step_robots(A,base):
		B=robots_analyze(base,A.session)
		if B:A.q.put((_B,{_A:'[Robots] sensitive disallows',_C:_I,_D:B}))
	def step_directories(B,base):
		A=[]
		for E in DIR_BRUTE:
			F=urljoin(base,E);D=safe_req(_N,F,session=B.session)
			if isinstance(D,Exception):continue
			if D.status_code in(200,301,302,307,308,401,403):A.append({_Z:E,_e:D.status_code,_F:F})
		if A:
			B.q.put((_B,{_A:f"[Dir] {len(A)} entries",_C:_I}))
			for C in A[:5]:B.q.put((_B,{_A:f"[Dir] {C[_Z]} -> {C[_e]}",_C:_S}))
			for C in A:B.add_find(make_finding('Dizin keşfi',_M,C[_Z],C[_F]))
		B.q.put((_B,{_H:('directories',A),_A:''}))
	def step_ports(A,host):
		try:
			C=socket.gethostbyname(host);B=port_scan_top(C)
			if B:A.q.put((_B,{_A:f"[Ports] Open: {", ".join(map(str,B))}",_C:_I,_K:make_finding('Açık servisler',_P,f"Ports: {B}",host)}))
			else:A.q.put((_B,{_A:'[Ports] none found',_C:_O}))
			A.q.put((_B,{_H:('ports',B),_A:''}))
		except Exception as D:A.q.put((_B,{_A:f"[Ports] error: {D}",_C:_I}))
	def step_xss(A,base):
		B=xss_quick(base,A.session)
		if B.get(_G):A.q.put((_B,{_A:f"[XSS] error: {B[_G]}",_C:_I}))
		elif B[_D]:
			for C in B[_D]:A.q.put((_B,{_A:f"[XSS] {C[_R]} → {C[_F]}",_C:_Q,_K:make_finding('XSS',_T,C[_R],C[_F])}))
		else:A.q.put((_B,{_A:'[XSS] none (quick)',_C:_O}))
		A.q.put((_B,{_H:('xss',B),_A:''}))
	def step_sqli(A,base):
		C=sqli_test(base,A.session)
		if C[_D]:
			for B in C[_D]:A.q.put((_B,{_A:f"[SQLi] {B[_R]} → {B[_F]}",_C:_Q,_K:make_finding('SQL Injection',_r,B[_R],B[_F])}))
		else:A.q.put((_B,{_A:'[SQLi] none (error-based)',_C:_O}))
		A.q.put((_B,{_H:('sqli',C),_A:''}))
	def step_lfi(A,base):
		B=lfi_test(base,A.session)
		if B[_D]:
			for C in B[_D]:A.q.put((_B,{_A:f"[LFI] → {C[_F]}",_C:_Q,_K:make_finding('Local File Inclusion',_r,url=C[_F])}))
		else:A.q.put((_B,{_A:'[LFI] none',_C:_O}))
		A.q.put((_B,{_H:('lfi',B),_A:''}))
	def step_redirect_open(A,base):
		B=open_redirect_test(base,A.session)
		if B[_D]:
			for C in B[_D]:A.q.put((_B,{_A:f"[OpenRedirect] → {C[_F]}",_C:_Q,_K:make_finding(_AP,_T,url=C[_F])}))
		else:A.q.put((_B,{_A:'[OpenRedirect] none',_C:_O}))
		A.q.put((_B,{_H:('open_redirect',B),_A:''}))
	def step_ssti(A,base):
		B=ssti_test(base,A.session)
		if B[_D]:
			for C in B[_D]:A.q.put((_B,{_A:f"[SSTI] {C[_F]}",_C:_Q,_K:make_finding('SSTI',_r,C[_R],C[_F])}))
		else:A.q.put((_B,{_A:'[SSTI] none',_C:_O}))
		A.q.put((_B,{_H:('ssti',B),_A:''}))
	def step_idor(A,base):
		B=idor_quick(base,A.session)
		if B[_D]:
			for C in B[_D]:A.q.put((_B,{_A:f"[IDOR] {C[_F]}",_C:_Q,_K:make_finding('IDOR (heuristic)',_T,C[_f],C[_F])}))
		else:A.q.put((_B,{_A:'[IDOR] none (quick)',_C:_O}))
		A.q.put((_B,{_H:('idor',B),_A:''}))
	def step_rate_limit(A,base):
		B=rate_limit_probe(base,10,A.session)
		if not B['flagged']:A.q.put((_B,{_A:'[RateLimit] görünür rate-limit yok',_C:_I,_K:make_finding('Rate limit eksik',_M,detail=str(B),url=base)}))
		A.q.put((_B,{_H:('rate_limit',B),_A:''}))
	def run_ai(A):
		A.log(t(_AH,A.lang.get()),_S);D=A.results.get(_D,[]);E=total_risk(D);F=sorted(D,key=lambda x:SEVERITY_WEIGHTS.get(x[_Y],0),reverse=_J)[:7];B=[f"# {t(_AG,A.lang.get())}",f"- Score: {E}",'- Top issues:']
		for C in F:B.append(f"  - [{C[_Y]}] {C[_U]} -> {C.get(_F,"")}")
		G=['Enable HSTS (max-age≥15552000, includeSubDomains, preload).','Set X-Frame-Options: DENY or SAMEORIGIN.','Add Content-Security-Policy without unsafe-inline; avoid wildcards.','Set X-Content-Type-Options: nosniff.',"Restrict CORS; avoid '*' especially with credentials.",'Add proper Cache-Control for sensitive responses.','Sanitize inputs; use parameterized queries to prevent SQLi.','Implement rate limiting and CAPTCHA where appropriate.'];B.append('- Remediation quick wins:');B+=[f"  - {A}"for A in G];A.log('\n'.join(B),_S);A.log(t(_A2,A.lang.get()),_O)
	def save(C,kind):
		L='Helvetica-Bold';K='utf-8';J='PDF';H='Helvetica';D=kind
		if D not in(_W,_X,_b):return
		if D==_b and not HAS_PDF:messagebox.showerror(J,t(_AD,C.lang.get()));return
		E=filedialog.asksaveasfilename(defaultextension=f".{D}",filetypes=[('Text','*.txt')]if D==_W else[('JSON','*.json')]if D==_X else[(J,'*.pdf')])
		if not E:return
		try:
			if D==_W:
				M=C.console.get('1.0',tk.END).strip()
				with open(E,'w',encoding=K)as F:F.write(M)
			elif D==_X:
				C.results['risk_score']=total_risk(C.results[_D])
				with open(E,'w',encoding=K)as F:json.dump(C.results,F,ensure_ascii=_V,indent=2)
			else:
				A=canvas.Canvas(E,pagesize=A4);Q,I=A4;B=I-40;A.setFont(L,14);A.drawString(40,B,APP_TITLE);B-=18;A.setFont(H,10);A.drawString(40,B,time.strftime(_AQ));B-=16;N=total_risk(C.results.get(_D,[]));A.drawString(40,B,f"Risk Score: {N}");B-=20;A.setFont(L,12);A.drawString(40,B,'Findings:');B-=16;A.setFont(H,10)
				for G in C.results.get(_D,[])[:60]:
					O=f"[{G[_Y]}] {G[_U]} - {G.get(_F,"")}";A.drawString(40,B,O[:110]);B-=12
					if B<60:A.showPage();B=I-40;A.setFont(H,10)
				A.showPage();A.save()
			messagebox.showinfo('OK',f"{t(_AE,C.lang.get())}: {E}")
		except Exception as P:messagebox.showerror('Hata',f"{t(_AF,C.lang.get())}: {P}")
if __name__=='__main__':root=tk.Tk();app=App(root);root.minsize(1024,720);root.mainloop()
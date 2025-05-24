import numpy as np
import pandas as pd
import joblib
from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP
from scapy.all import get_if_list, get_if_addr
import time
from rotor.model import Model

class Captor:
    global captura
    captura = False
    
    def __init__(self):
        self.fluxos_ativos = {}
        self.fluxos_finalizados = []
        self.inicio_geral = time.time()
        self.sniffer = None
        self.resultados_fluxos = []
        
        # Carregando os PCA treinados   
        self.pca = joblib.load('rotor/PCA/pca_active_profile.pkl')
        self.pca2 = joblib.load('rotor/PCA/pca_fwd_packet_length_profile.pkl')
        self.pca3 = joblib.load('rotor/PCA/pca_total_packets_profile.pkl')
        self.pca4 = joblib.load('rotor/PCA/pca_iat_idle_partial.pkl')
        self.pca5 = joblib.load('rotor/PCA/pca_fwd_iat_idle_profile.pkl')
        self.pca6 = joblib.load('rotor/PCA/pca_segment_len_profile.pkl')
        self.pca7 = joblib.load('rotor/PCA/pca_idle_profile.pkl')
        
    def extrair_iface(self):
        ip = get_if_addr(conf.iface)
        ifaces = get_if_list()
        for iface in ifaces:
            try:
                ip_iface = get_if_addr(iface)
                if ip == ip_iface:
                    return iface
            except Exception as e:
                print(f"[ERROR] Erro ao obter o IP da interface {iface}: {e}")
                pass
    
    def iniciar_captura(self):
        global sniffer
        global captura
        captura = True
        
        iface = self.extrair_iface()   
        print(f'[INFO] Interface de captura: {iface}') 

        sniffer = AsyncSniffer(
            prn=self.processar_pacote,
            store=False,
            filter="ip",
            iface=iface 
        )

        sniffer.start()
        print("[INFO] Captura iniciada...")
        
        
    @staticmethod
    def extrair_chave_fluxo(pkt):
        if IP in pkt:
            ip = pkt[IP]
            if TCP in pkt:
                proto = 'TCP'
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = 'UDP'
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                proto = 'OTHER'
                sport = 0
                dport = 0
            return (ip.src, ip.dst, sport, dport, proto)
        return None

    def processar_pacote(self, pkt):
        chave = self.extrair_chave_fluxo(pkt)
        if not chave:
            return

        agora = time.time()

        if chave not in self.fluxos_ativos:
            self.fluxos_ativos[chave] = {
                'inicio': agora,
                'ultimo': agora,
                'bytes_fwd': 0,
                'bytes_bwd': 0,
                'qtd_fwd': 0,
                'qtd_bwd': 0,
                'iat': [],
                'iat_fwd': [],
                'iat_bwd': [],
                'tamanhos': [],
                'tamanhos_fwd': [],
                'tamanhos_bwd': [],
                'urg_count': 0,
                'psh_count': 0,
                'header_len_fwd': 0,
                'header_len_bwd': 0,
                'FIN Flag Count': 0,
                'ACK Flag Count': 0,
                'RST Flag Count': 0,
                'PSH Flag Count': 0,
                'URG Flag Count': 0,
                'ECE Flag Count': 0,
                'fwd_segment_sizes': [],
                'bwd_segment_sizes': [],
                'subflow_bytes_fwd': 0,
                'subflow_bytes_bwd': 0,
                'Init_Win_bytes_forward': None,
                'Init_Win_bytes_backward': None,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': None,
                'timestamps_fwd': [],
            }

        fluxo = self.fluxos_ativos[chave]
        fluxo['Destination Port'] = pkt.dport if TCP in pkt else 0
        duracao = agora - fluxo['ultimo']
        fluxo['ultimo'] = agora

        tam = len(pkt)
        direcao = 'fwd' if pkt[IP].src == chave[0] else 'bwd'

        if direcao == 'fwd':
            fluxo['bytes_fwd'] += tam
            fluxo['qtd_fwd'] += 1
            fluxo['subflow_bytes_fwd'] += tam
            fluxo['tamanhos_fwd'].append(tam)
            fluxo['iat_fwd'].append(duracao)
            fluxo['timestamps_fwd'].append(agora)
            
            if pkt.haslayer(TCP):
                payload_len = len(pkt[TCP].payload)
                if payload_len > 0:
                    fluxo['act_data_pkt_fwd'] += 1
        else:
            fluxo['bytes_bwd'] += tam
            fluxo['qtd_bwd'] += 1
            fluxo['subflow_bytes_bwd'] += tam
            fluxo['tamanhos_bwd'].append(tam)
            fluxo['iat_bwd'].append(duracao)
            

        fluxo['tamanhos'].append(tam)
        fluxo['iat'].append(duracao)
        
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            tam_segmento = len(pkt[TCP].payload)
            
            seg_size = len(pkt[TCP].payload)
            if fluxo['min_seg_size_forward'] is None or seg_size < fluxo['min_seg_size_forward']:
                fluxo['min_seg_size_forward'] = seg_size
            
            if flags & 0x01:  # FIN
                fluxo['FIN Flag Count'] += 1
            if flags & 0x10:  # ACK
                fluxo['ACK Flag Count'] += 1
            if flags & 0x04:  # RST
                fluxo['RST Flag Count'] += 1
            if flags & 0x08:  # PSH
                fluxo['PSH Flag Count'] += 1
            if flags & 0x20:  # URG
                fluxo['URG Flag Count'] += 1
            if flags & 0x40:  # ECE
                fluxo['ECE Flag Count'] += 1

            if direcao == 'fwd':
                fluxo['fwd_segment_sizes'].append(tam_segmento)
                
                if flags & 0x20:  # URG
                    fluxo['urg_count'] += 1
                if flags & 0x08:  # PSH
                    fluxo['psh_count'] += 1
                    
                if fluxo['Init_Win_bytes_forward'] is None:
                    fluxo['Init_Win_bytes_forward'] = pkt[TCP].window
                    
            else:
                fluxo['bwd_segment_sizes'].append(tam_segmento)
                
                if fluxo['Init_Win_bytes_backward'] is None:
                    fluxo['Init_Win_bytes_backward'] = pkt[TCP].window
                
                
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_header_len = pkt[IP].ihl * 4  # IHL está em múltiplos de 4 bytes
            tcp_header_len = pkt[TCP].dataofs * 4  # dataofs também em múltiplos de 4 bytes
            total_header_len = ip_header_len + tcp_header_len

            if direcao == 'fwd':
                fluxo['header_len_fwd'] += total_header_len
            else:
                fluxo['header_len_bwd'] += total_header_len
        
    def encerrar_todos_fluxos(self):
        for chave, fluxo in list(self.fluxos_ativos.items()):
            print(f"[INFO] Encerrando fluxo: {chave}")
            features = self.extrair_features_fluxo(fluxo)
            resultado = self.processar_fluxo(features)
            self.resultados_fluxos.append(resultado)
            del self.fluxos_ativos[chave]

    def extrair_features_fluxo(self, fluxo):
        atividades = []
        
        if (fluxo['ultimo'] - fluxo['inicio']) > 0:
            FwdPackets = fluxo['qtd_fwd'] / (fluxo['ultimo'] - fluxo['inicio'])
            BwdPackets = fluxo['qtd_bwd'] / (fluxo['ultimo'] - fluxo['inicio'])
        else:
            FwdPackets = 0
            BwdPackets = 0
            
        timestamps = fluxo.get('timestamps_fwd', [])
        if len(timestamps) >= 2:
            atividades = []
            start = timestamps[0]
            for i in range(1, len(timestamps)):
                if timestamps[i] - timestamps[i - 1] > 1.0:  
                    atividade = timestamps[i - 1] - start
                    if atividade > 0:
                        atividades.append(atividade)
                    start = timestamps[i]
            
            atividade = timestamps[-1] - start
            if atividade > 0:
                atividades.append(atividade)
                
        idle_times = []
        for t in fluxo['iat']:
            if t > 1:  
                idle_times.append(t)
        
        return {
            'Destination Port': fluxo['Destination Port'],
            'Total Length of Fwd Packets': fluxo['bytes_fwd'],
            'Fwd Packet Length Min': min(fluxo['tamanhos_fwd']) if fluxo['tamanhos_fwd'] else 0,
            'Bwd Packet Length Max': max(fluxo['tamanhos_bwd']) if fluxo['tamanhos_bwd'] else 0,
            'Bwd Packet Length Min': min(fluxo['tamanhos_bwd']) if fluxo['tamanhos_bwd'] else 0,
            'Bwd Packet Length Mean': np.mean(fluxo['tamanhos_bwd']) if fluxo['tamanhos_bwd'] else 0,
            'Bwd Packet Length Std': np.std(fluxo['tamanhos_bwd']) if fluxo['tamanhos_bwd'] else 0,
            'Flow Bytes/s': fluxo['bytes_fwd'] / (fluxo['ultimo'] - fluxo['inicio']) if (fluxo['ultimo'] - fluxo['inicio']) > 0 else 0,
            'Flow Packets/s': (fluxo['qtd_fwd'] + fluxo['qtd_bwd']) / (fluxo['ultimo'] - fluxo['inicio']) if (fluxo['ultimo'] - fluxo['inicio']) > 0 else 0,
            'Flow IAT Mean': np.mean(fluxo['iat']) if fluxo['iat'] else 0,
            'Flow IAT Max': max(fluxo['iat']) if fluxo['iat'] else 0,
            'Flow IAT Std': np.std(fluxo['iat']) if fluxo['iat'] else 0,
            'Flow IAT Min': min(fluxo['iat']) if fluxo['iat'] else 0,
            'Fwd IAT Mean': np.mean(fluxo['iat_fwd']) if fluxo['iat_fwd'] else 0,
            'Total Length of Bwd Packets': fluxo['bytes_bwd'],
            'Flow Duration': fluxo['ultimo'] - fluxo['inicio'],
            'Total Fwd Packets': fluxo['qtd_fwd'],
            'Total Backward Packets': fluxo['qtd_bwd'],
            'Fwd Packet Length Max': max(fluxo['tamanhos_fwd']) if fluxo['tamanhos_fwd'] else 0,    
            'Fwd Packet Length Mean': np.mean(fluxo['tamanhos_fwd']) if fluxo['tamanhos_fwd'] else 0,
            'Fwd Packet Length Std': np.std(fluxo['tamanhos_fwd']) if fluxo['tamanhos_fwd'] else 0,
            'Bwd Packet Length Max': max(fluxo['tamanhos_bwd']) if fluxo['tamanhos_bwd'] else 0,
            'Fwd IAT Total': sum(fluxo['iat_fwd']) if fluxo['iat_fwd'] else 0,
            'Fwd IAT Std': np.std(fluxo['iat_fwd']) if fluxo['iat_fwd'] else 0,
            'Fwd IAT Max': max(fluxo['iat_fwd']) if fluxo['iat_fwd'] else 0,
            'Fwd IAT Min': min(fluxo['iat_fwd']) if fluxo['iat_fwd'] else 0,
            'Bwd IAT Total': sum(fluxo['iat_bwd']) if fluxo['iat_bwd'] else 0,
            'Bwd IAT Mean': np.mean(fluxo['iat_bwd']) if fluxo['iat_bwd'] else 0,
            'Bwd IAT Std': np.std(fluxo['iat_bwd']) if fluxo['iat_bwd'] else 0,
            'Bwd IAT Max': max(fluxo['iat_bwd']) if fluxo['iat_bwd'] else 0,
            'Bwd IAT Min': min(fluxo['iat_bwd']) if fluxo['iat_bwd'] else 0,
            'Fwd PSH Flags': fluxo['psh_count'],
            'Fwd URG Flags': fluxo['urg_count'],
            'Fwd Header Length': fluxo['header_len_fwd'],
            'Bwd Header Length': fluxo['header_len_bwd'],
            'Fwd Packets/s': FwdPackets,
            'Bwd Packets/s': BwdPackets,
            'Max Packet Length': max(fluxo['tamanhos']) if fluxo['tamanhos'] else 0,
            'Min Packet Length': min(fluxo['tamanhos']) if fluxo['tamanhos'] else 0,
            'Packet Length Mean': np.mean(fluxo['tamanhos']) if fluxo['tamanhos'] else 0,
            'Packet Length Std': np.std(fluxo['tamanhos']) if fluxo['tamanhos'] else 0,
            'Packet Length Variance': np.var(fluxo['tamanhos']) if fluxo['tamanhos'] else 0,
            'FIN Flag Count': fluxo['FIN Flag Count'],
            'RST Flag Count': fluxo['RST Flag Count'],
            'PSH Flag Count': fluxo['PSH Flag Count'],
            'ACK Flag Count': fluxo['ACK Flag Count'],
            'URG Flag Count': fluxo['URG Flag Count'],
            'ECE Flag Count': fluxo['ECE Flag Count'],
            'Down/Up Ratio': fluxo['qtd_bwd'] / fluxo['qtd_fwd'] if fluxo['qtd_fwd'] > 0 else 0,
            'Average Packet Size': sum(fluxo['tamanhos']) / len(fluxo['tamanhos']),
            'Avg Fwd Segment Size': sum(fluxo['fwd_segment_sizes']) / len(fluxo['fwd_segment_sizes']) if fluxo['fwd_segment_sizes'] else 0,
            'Avg Bwd Segment Size': sum(fluxo['bwd_segment_sizes']) / len(fluxo['bwd_segment_sizes']) if fluxo['bwd_segment_sizes'] else 0,
            'Subflow Fwd Bytes': fluxo['subflow_bytes_fwd'],
            'Subflow Bwd Bytes': fluxo['subflow_bytes_bwd'],
            'Init_Win_bytes_forward': fluxo['Init_Win_bytes_forward'],
            'Init_Win_bytes_backward': fluxo['Init_Win_bytes_backward'],
            'act_data_pkt_fwd': fluxo['act_data_pkt_fwd'],
            'min_seg_size_forward': fluxo['min_seg_size_forward'],
            'Active Mean': np.mean(atividades) if atividades else 0,
            'Active Std': np.std(atividades) if atividades else 0,
            'Active Max': max(atividades) if atividades else 0,
            'Active Min': min(atividades) if atividades else 0,
            'Idle Mean': np.mean(idle_times) if idle_times else 0,
            'Idle Std': np.std(idle_times) if idle_times else 0,
            'Idle Max': max(idle_times) if idle_times else 0,
            'Idle Min': min(idle_times) if idle_times else 0,
        }

    def processar_fluxo(self, dado):
        df = pd.DataFrame([dado])

        # Aplicando transformações e PCA
        df['Active_Profile'] = self.pca.transform(df[['Active Mean', 'Active Std', 'Active Max', 'Active Min']])
        df['Fwd Packet Length_Profile'] = self.pca2.transform(df[['Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std']])
        df['Total Packets and Subflow Bwd Profile'] = self.pca3.transform(df[['Total Length of Bwd Packets', 'Subflow Bwd Bytes', 'Total Fwd Packets', 'Total Backward Packets']])

        df['Fwd Flow IAT Max'] = (df['Flow IAT Max'] + df['Fwd IAT Max']) / 2
        df['Idle Mean and Max Profile'] = self.pca4.transform(df[['Idle Mean', 'Idle Max']])
        df['Fwd Flow IAT Max and Idle Profile'] = self.pca5.transform(df[['Fwd Flow IAT Max', 'Idle Mean and Max Profile']])

        df['RST Plus ECE Flag Count'] = df['RST Flag Count'] + df['ECE Flag Count']
        df['Flow Duration Fwd IAT Total'] = np.where(
            df['Fwd IAT Total'] != 0,
            df['Flow Duration'] / df['Fwd IAT Total'],
            df['Flow Duration']
        )
        df['Fwd Avg Segement and Packet Length Mean profile'] = self.pca6.transform(df[['Avg Fwd Segment Size', 'Fwd Packet Length Mean']])
        df['Idle_Profile'] = self.pca7.transform(df[['Idle Mean', 'Idle Max', 'Idle Min']])

        # Dropa colunas que foram agregadas via PCA
        colunas_para_remover = [
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Total Length of Bwd Packets', 'Subflow Bwd Bytes', 'Total Fwd Packets', 'Total Backward Packets',
            'Flow IAT Max', 'Fwd IAT Max', 'Fwd Flow IAT Max', 'Idle Mean and Max Profile',
            'RST Flag Count', 'ECE Flag Count',
            'Flow Duration', 'Fwd IAT Total',
            'Avg Fwd Segment Size', 'Idle Mean', 'Idle Max', 'Idle Min'
        ]
        df.drop(columns=colunas_para_remover, inplace=True, errors='ignore')
        
        ordem_colunas = [
            'Destination Port', 'Total Length of Fwd Packets', 'Fwd Packet Length Min',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Bwd Segment Size',
            'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward', 'Idle Std',
            'Active_Profile', 'Fwd Packet Length_Profile',
            'Total Packets and Subflow Bwd Profile', 'Fwd Flow IAT Max and Idle Profile',
            'RST Plus ECE Flag Count', 'Flow Duration Fwd IAT Total',
            'Fwd Avg Segement and Packet Length Mean profile', 'Idle_Profile'
        ]
        
        df= df.reindex(columns=ordem_colunas)

        return df

    def parar_captura(self, tempo):
        global sniffer
        global captura
        
        print(f"[INFO] A captura vai durar {tempo} segundos.")
        time.sleep(tempo)
        
        captura = False
        print("[INFO] Encerrando todos os fluxos ativos...")
        self.encerrar_todos_fluxos()
            
    def show(self):
        if self.resultados_fluxos:
            df_final = pd.concat(self.resultados_fluxos, ignore_index=True)
            pd.set_option('display.max_columns', None)
            print(df_final)
        else:
            print("Nenhum fluxo capturado.")
            
    def classificar_fluxo(self):
        # Junta os resultados dos fluxos numa tabela (pandas DataFrame)
        df_final = pd.concat(self.resultados_fluxos, ignore_index=True)
        
        # Cria a instância do modelo
        model = Model()
        
        # Passa os dados para o método classify e pega o resultado
        resultado = model.classify(df_final)
        
        return resultado

if __name__ == "__main__":
    
    captor = Captor()
    captor.iniciar_captura()
    
    tempo = 30
    
    captor.parar_captura(tempo)
    
    if captor.resultados_fluxos:
        df_final = pd.concat(captor.resultados_fluxos, ignore_index=True)
        pd.set_option('display.max_columns', None)
        print(df_final)
        
        resultado = captor.classificar_fluxo()
        print(resultado)
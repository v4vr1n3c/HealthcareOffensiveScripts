
# HL7 Server Scanner

###   **Para que serve?**:
Durante um pentest precisamos levantar o máximo de informações de servidores que transmitem HL7, para isso foi desenvolvido o script para automatizar a atividades e acelerar o engagement.

###   **Instalar as Dependências**:
     
		`pip install python-nmap` 
    
### Explicação do Script:

1.  **scan_hl7(ip_range, port=2575)**: Esta função usa `nmap` para escanear uma faixa de IPs (`ip_range`) em busca de dispositivos com a porta HL7 (2575) aberta.
2.  **check_hl7_service(ip, port)**: Esta função tenta estabelecer uma conexão com a aplicação HL7 e enviar uma mensagem de teste HL7. Se uma resposta válida for recebida, considera-se que o serviço HL7 está ativo.
3.  **Main**: Solicita ao usuário a faixa de IPs a ser escaneada, realiza o scan e imprime os dispositivos que têm serviços HL7.

### Como Usar:

1.  **Execute o script**:

	    `python3 hl7_scanner.py` 
    
2.  **Insira a faixa de IPs** a ser escaneada (por exemplo, `192.168.1.0/24`).

O script irá escanear a faixa de IPs fornecida, verificar se a porta 2575 (ou outra porta específica de HL7) está aberta e tentar enviar uma mensagem HL7 para confirmar a presença do serviço.

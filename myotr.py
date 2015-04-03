__module_name__ = 'myotr'
__module_author__ = 'SpiralP'
__module_version__ = '1'
__module_description__ = 'OTR for HexChat'

import sys
import os

import urllib2
import hashlib

import hexchat
import potr

GIT_URL='https://github.com/SpiralP/HexChat-otr'
REMOTE_FILE='https://raw.githubusercontent.com/SpiralP/HexChat-otr/master/myotr.py'
STATUS_URL='https://api.github.com/repos/SpiralP/HexChat-otr/git/refs'

CONFIG_DIR=hexchat.get_info('configdir')
OTR_DIR=os.path.join(CONFIG_DIR, 'otr')

CLEAR='\017'
BOLD='\002'
UNDERLINE='\037'
COLOR='\003'
RED=COLOR+'04'
GREEN=COLOR+'03'
BLUE=COLOR+'02'

DEFAULT_POLICY_FLAGS = {
	'ALLOW_V1':False,
	'ALLOW_V2':True,
	'REQUIRE_ENCRYPTION':True,
}
# 'SEND_TAG':True, # basically advertise your version

PROTOCOL='irc'
MMS=400


accounts = {}


class PythonVersion2(object):
	def __init__(self):
		return
	
	def to_unicode(self, str): # utf8 -> unicode
		if isinstance(str, unicode):
			return str
		else:
			return str.decode('utf-8', 'replace')
	
	def to_str(self, str): # unicode -> utf8
		return str.encode('utf-8', 'replace')
	
class PythonVersion3(object):
	def __init__(self, minor):
		self.minor = minor
	
	def to_unicode(self, str): # utf8 -> unicode
		if isinstance(str, bytes):
			return str.decode('utf-8', 'replace')
		else:
			return str
	
	def to_str(self, str): # unicode -> utf8
		return str
	
if sys.version_info.major >= 3:
	PYVER = PythonVersion3(sys.version_info.minor)
else:
	PYVER = PythonVersion2()



def success(msg):
	hexchat.prnt(BOLD + GREEN + msg)
def info(msg):
	hexchat.prnt(BOLD + BLUE + msg)
def warn(msg):
	hexchat.prnt(BOLD + RED + msg)

def first_instance(objs, Class):
	for obj in objs:
		if isinstance(obj, Class):
			return obj

def getAccount(id=None):
	if id is None:
		name = hexchat.get_info('nick')
		if name is None:
			return False
		
		network = hexchat.get_info('network')
		if network is None:
			return False
		
		id = name+'@'+network
	
	if id not in accounts:
		hexchat.prnt(BLUE+'Creating new account for: %s' % id)
		accounts[id] = MyAccount(id)
	
	return accounts[id]
def getChannel():
	return hexchat.get_info('channel')

def say(who,msg):
	for line in msg.split('\n'):
		hexchat.command('PRIVMSG %s :%s' % (who,line))
	return


updateChecked=False
def updateCheck():
	global updateChecked
	if not updateChecked:
		updateChecked=True
		
		try:
			http = urllib2.urlopen(REMOTE_FILE)
		except:
			warn('Error retrieving update data!')
			return False
		
		remotedata = http.read()
		http.close()
		
		localpath = os.path.join(CONFIG_DIR,'addons')
		localpath = os.path.join(localpath,'myotr.py')
		
		try:
			with open(localpath, 'rb') as file:
				localdata = file.read()
		except:
			warn('Error reading local file!')
			return False
		file.close()
		
		remotehash = hashlib.sha1(remotedata).hexdigest()
		localhash = hashlib.sha1(localdata).hexdigest()
		
		
		
		updateAvailable = (remotehash!=localhash)
		if updateAvailable:
			success('New Update Available! Get it from: %s' % (UNDERLINE+BLUE+GIT_URL))
		else:
			info('Your version of %s is up to date!' % __module_name__)
		
		return True
	return



class MyContext(potr.context.Context):
	
	def __init__(self, account, peer):
		super(MyContext, self).__init__(account, peer)
		self.in_smp = False
		self.smp_question = False
	
	def getPolicy(self, key):
		if key in DEFAULT_POLICY_FLAGS:
			return DEFAULT_POLICY_FLAGS[key]
		else:
			return False
	
	def inject(self, msg, appdata=None):
		say(self.peer,msg)
	
	def setState(self, newstate):
		oldstate = self.state
		
		desc = 'WOT'
		if newstate==potr.context.STATE_PLAINTEXT:
			desc = 'Plain Text'
		elif newstate==potr.context.STATE_ENCRYPTED:
			desc = 'Encrypted'
		elif newstate==potr.context.STATE_FINISHED:
			desc = 'Finished!'
		success('NEW STATE: ' + BLUE + desc)
		
		
		# started with encryption
		if not(oldstate==potr.context.STATE_ENCRYPTED) and (newstate==potr.context.STATE_ENCRYPTED):
			
			trust = self.getCurrentTrust()
			
			if trust is None:
				info('Fingerprint: %s' % str(self.getCurrentKey()))
			
			if bool(trust):
				success('AUTHENTICATED')
			else:
				warn('UNAUTHENTICATED!!!')
			
			
		if oldstate!=potr.context.STATE_PLAINTEXT and newstate==potr.context.STATE_PLAINTEXT:
			info('conversation ended!')
		
		super(MyContext, self).setState(newstate)
		
	def smpFinish(self):
		self.in_smp = False
		self.smp_question = False
		self.user.saveTrusts()
	
	def handleTLV(self, data):
		smp1q = first_instance(data, potr.proto.SMP1QTLV)
		smp3  = first_instance(data, potr.proto.SMP3TLV)
		smp4  = first_instance(data, potr.proto.SMP4TLV)
		
		if first_instance(data, potr.proto.SMPABORTTLV):
			warn('SMP aborted by peer ( might mean they guessed a wrong password )')
		elif self.in_smp and not self.smpIsValid():
			warn('SMP aborted?')
		elif first_instance(data, potr.proto.SMP1TLV):
			self.in_smp = True
			info('Peer requested SMP verification.\nUse /otr smp respond <secret>')
		elif smp1q:
			self.in_smp = True
			self.smp_question = True
			
			info('Peer requested SMP verification: "%s"\nUse /otr smp respond <secret>' % PYVER.to_unicode(smp1q.msg))
		elif first_instance(data, potr.proto.SMP2TLV):
			if not self.in_smp:
				self.smpFinish()
			else:
				info('SMP processing...')
		elif smp3 or smp4:
			if smp3:
				info('smp3')
			if smp4:
				info('smp4')
			if self.smpIsSuccess():
				if self.smp_question:
					self.smpFinish()
					success('SMP verification succeeded!')
					if not bool(self.getCurrentTrust()):
						warn('You do not yet trust your peer, try asking your own question: /otr smp ask [question] <secret>')
				else:
					self.smpFinish()
					success('SMP verification succeeded!')
			else:
				self.smpFinish()
				warn('SMP verification FAILED!')
	
class MyAccount(potr.context.Account):
	
	#important lol
	contextclass = MyContext
	
	def __init__(self, id):
		global PROTOCOL, MMS
		super(MyAccount, self).__init__(id, PROTOCOL, MMS)
		
		if not os.path.exists(OTR_DIR):
			info('Creating new directory: %s' % OTR_DIR)
			os.makedirs(OTR_DIR)
		
		self.keyFilePath=os.path.join(OTR_DIR, '{}.key3'.format(id))
		self.trustsFilePath=os.path.join(OTR_DIR, '{}.trusts'.format(id))
		
		
		self.loadTrusts()
	
	def loadPrivkey(self):
		info('Loading Private Key')
		
		if not os.path.exists(self.keyFilePath):
			return None
		
		try:
			with open(self.keyFilePath, 'rb') as file:
				return potr.crypt.PK.parsePrivateKey(file.read())[0]
		except IOError, e:
			pass
		return None
	
	def savePrivkey(self):
		info('Saving Private Key')
		
		if not os.path.exists(self.keyFilePath):
			info('Creating new file: %s' % self.keyFilePath)
		
		with open(self.keyFilePath, 'wb') as file:
			file.write(self.getPrivkey().serializePrivateKey())
		
		return
	
	def loadTrusts(self):
		info('Loading Trusts')
		if not os.path.exists(self.trustsFilePath):
			return
		
		with open(self.trustsFilePath, 'rb') as file:
			for line in file:
				context, account, fingerprint, trust = PYVER.to_unicode(line[:-1]).split('\t')
				if account == self.name:
					info('trusting %s %s' % (fingerprint,trust))
					self.setTrust(context, fingerprint, trust)
		return
	def saveTrusts(self):
		info('Saving Trusts')
		
		with open(self.trustsFilePath,'wb') as file:
			for uid, trusts in self.trusts.items():
				for fingerprint, trust in trusts.items():
					info('writing %s %s' % (fingerprint,trust))
					file.write(
						PYVER.to_str(
							'\t'.join((uid, self.name, fingerprint, trust))
						)
					)
					file.write('\n')
		
		return



def message_callback(word, word_eol, userdata):
	who = word[0]
	msg = word[1]
	
	account = getAccount()
	if not account:
		return hexchat.EAT_NONE
	
	chan = getChannel()
	
	if chan not in account.ctxs:
		return hexchat.EAT_NONE
	context = account.getContext(chan) # or who? for channels?
	
	try: # TODO handle more things
		msg,data = context.receiveMessage(msg)
		
		context.handleTLV(data)
	except potr.context.UnencryptedMessage:
		return hexchat.EAT_NONE
	
	if msg is None:
		return hexchat.EAT_ALL
	
	hexchat.prnt(BLUE+'<-'+msg)
	
	return hexchat.EAT_ALL

def keypress(word, word_eol, userdata):
	key = word[0]
	alt = word[1]
	letter = word[2]
	
	if not(key=='65293'): # return key
		return
	
	
	msg = hexchat.get_info('inputbox')
	
	if len(msg)==0 or msg[0]=='/':
		return hexchat.EAT_NONE
	
	
	
	account = getAccount()
	if not account:
		return hexchat.EAT_NONE
	
	chan = getChannel()
	
	if chan not in account.ctxs:
		return hexchat.EAT_NONE
	
	context = account.getContext(chan)
	
	if context.state==potr.context.STATE_ENCRYPTED:
		hexchat.prnt(BLUE + '->' + msg)
		context.sendMessage(0,msg)
		
		hexchat.command('settext') # the hacks
		
		return hexchat.EAT_ALL
	
	
	
	return hexchat.EAT_NONE


def command_callback(word, word_eol, userdata):
	
	updateCheck()
	
	
	
	account = getAccount()
	if not account:
		return hexchat.EAT_NONE
	
	chan = getChannel()
	
	if chan not in account.ctxs:
		hexchat.prnt(BLUE+'Adding context for: %s' % chan)
	context = account.getContext(chan)
	
	cmd = len(word)>1 and word[1] or ''
	
	
	if   cmd=='go':
		
		say(context.peer,context.sendMessage(0,'?OTR?')) # this will actually send the correct version-query
		info('Query Sent...')
		
	elif cmd=='stop':
		
		context.disconnect()
		
	elif cmd=='trust':
		
		context.setCurrentTrust('verified')
		
	elif cmd=='smp':
		if len(word)==2:
			return hexchat.EAT_ALL
		
		action = word[2]
		
		if action=='respond': # /otr smp respond secret
			secret = word[3]
			
			if secret:
				secret = PYVER.to_str(secret)
			
			context.smpGotSecret(secret)
			
			
			
		elif action=='ask':
			question = None
			secret = None
			
			if len(word)==4: # /otr smp ask secret
				secret = word[3]
				
			elif len(word)==5: # /otr smp ask question secret
				question = word[3]
				secret = word[4]
			else:
				return hexchat.EAT_ALL
			
			if secret:
				secret = PYVER.to_str(secret)
			if question:
				question = PYVER.to_str(question)
			
			
			try:
				context.smpInit(secret, question)
			except potr.context.NotEncryptedError:
				warn('No session with %s' % context.peer)
				return hexchat.EAT_ALL
			else: # except-else wtf python
				if question:
					info('SMP question sending...')
				else:
					info('SMP challenge sending...')
		
		elif action=='abort':
			
			try:
				context.smpAbort()
			except potr.context.NotEncryptedError:
				warn('No session with %s' % context.peer)
			else:
				info('SMP aborted')
		
		
	elif cmd=='send':
		
		context.sendMessage(0,word[3])
	
	
	
	
	return hexchat.EAT_ALL


hexchat.hook_print('Private Message to Dialog',message_callback)
hexchat.hook_print('Key Press',keypress)
hexchat.hook_command('otr',command_callback)

print('%s version %s loaded.' % (__module_name__,__module_version__))


getAccount()

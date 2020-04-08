import email
import os
import random
from io import BytesIO
import sys
import base64
import base36
from zope.interface import implementer

from twisted.cred import checkers, portal
from twisted.internet import protocol, reactor
from twisted.mail import imap4
from twisted.python import log

import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# TEMP Google authentication, from https://developers.google.com/gmail/api/quickstart/python
# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

creds = None
# The file token.pickle stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
if os.path.exists('token.pickle'):
	with open('token.pickle', 'rb') as token:
		creds = pickle.load(token)
# If there are no (valid) credentials available, let the user log in.
if not creds or not creds.valid:
	if creds and creds.expired and creds.refresh_token:
		creds.refresh(Request())
	else:
		flow = InstalledAppFlow.from_client_secrets_file(
			'credentials.json', SCOPES)
		creds = flow.run_local_server(port=0)
	# Save the credentials for the next run
	with open('token.pickle', 'wb') as token:
		pickle.dump(creds, token)

service = build('gmail', 'v1', credentials=creds)

# End Google authentication

@implementer(imap4.IAccount)
class IMAPUserAccount(object):

	def __init__(self):
		self.labels = [label for label in service.users().labels().list(userId='me').execute().get('labels', []) if label['name'] == 'INBOX'] # TODO: remove filter

	def listMailboxes(self, ref, wildcard):
		for index, label in enumerate(self.labels):
			yield label['name'], IMAPMailbox(index, label)

	def select(self, path, rw=False):
		for index, clabel in enumerate(self.labels):
			if clabel['name'] == path:
				return IMAPMailbox(index, clabel)
		return None

	def isSubscribed(self, name):
		return True

@implementer(imap4.IMailbox)
class IMAPMailbox(object):

	def __init__(self, mid, label):
		labelIds = [label['id']]
		response = service.users().messages().list(userId='me', labelIds=labelIds).execute()
		self.messages = []
		if 'messages' in response:
			self.messages.extend(response['messages'])
		while 'nextPageToken' in response:
			page_token = response['nextPageToken']
			response = service.users().messages().list(userId='me', labelIds=labelIds, pageToken=page_token).execute()
			self.messages.extend(response['messages'])
		self.listeners = []
		self.uniqueValidityIdentifier = mid

	def getHierarchicalDelimiter(self):
		return "_"

	def getFlags(self):
		return []

	def getMessageCount(self):
		return len(self.messages)

	def getRecentCount(self):
		return 0

	def isWriteable(self):
		return False

	def getUIDValidity(self):
		return self.uniqueValidityIdentifier

	def requestStatus(self, names):
		return {}

	def _seqMessageSetToSeqDict(self, messageSet, uid):
		if not uid and not messageSet.last:
			messageSet.last = self.getMessageCount()

		seqMap = {}
		for index, messageNum in enumerate(messageSet):
			if uid or messageNum >= 0 and messageNum <= self.getMessageCount():
				seqMap[index + 1] = base36.dumps(messageNum) if uid else self.messages[index]['id']
		return seqMap

	def fetch(self, messages, uid):
		res = []
		next = uid and messages.getnext(0)
		for index, id in self._seqMessageSetToSeqDict(messages, uid).items():
			message = service.users().messages().get(userId='me', id=id, format='raw').execute()
			msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII')).decode()
			res.append((index, MaildirMessage(base36.loads(id), msg_str, [])))
		return res

	def addListener(self, listener):
		self.listeners.append(listener)

	def removeListener(self, listener):
		self.listeners.remove(listener)

	def store(self, messages, flags, mode, uid):
		pass

@implementer(imap4.IMessagePart)
class MaildirMessagePart(object):

	def __init__(self, message):
		self.message = message
		self.data = str(message)

	def getHeaders(self, negate, *names):
		if not names:
			names = self.message.keys()

		headers = {}
		if negate:
			for header in self.message.keys():
				if str(header).upper() not in names:
					headers[str(header).lower()] = self.message.get(header, '')
		else:
			for name in names:
				headers[str(name).lower()] = self.message.get(name, '')

		return headers

	def getBodyFile(self):
		return BytesIO(str(self.message.get_payload()).encode())

	def getSize(self):
		return len(self.data)

	def isMultipart(self):
		return self.message.is_multipart()

	def getSubPart(self, part):
		return MaildirMessagePart(self.message.get_payload(part))

@implementer(imap4.IMessage)
class MaildirMessage(MaildirMessagePart):

	def __init__(self, uid, message, flags):
		super().__init__(message)
		self.uid = uid
		self.message = email.message_from_string(message)
		self.flags = flags
		# self.date = date


	def getUID(self):
		return self.uid

	def getFlags(self):
		return self.flags

	def getInternalDate(self):
		return self.message.get('Date', '')

@implementer(portal.IRealm)
class MailUserRealm(object):

	def requestAvatar(self, avatarId, mind, *interfaces):
		if imap4.IAccount not in interfaces:
			raise NotImplementedError(
				"This realm only supports the imap4.IAccount interface.")
		avatar = IMAPUserAccount()
		return imap4.IAccount, avatar, lambda: None

class IMAPServerProtocol(imap4.IMAP4Server):
	def lineReceived(self, line):
		print("CLIENT:", line)
		print(super().lineReceived(line))

	def sendLine(self, line):
		super().sendLine(line)
		print("SERVER:", line)

class IMAPFactory(protocol.Factory):
	def __init__(self, portal):
		self.portal = portal

	def buildProtocol(self, addr):
		proto = IMAPServerProtocol()
		proto.portal = portal
		return proto

log.startLogging(sys.stdout)

portal = portal.Portal(MailUserRealm())
checker = checkers.FilePasswordDB('passwords.txt')
portal.registerChecker(checker)

reactor.listenTCP(143, IMAPFactory(portal))
reactor.run()

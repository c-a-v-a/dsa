from sys import argv

from dsa import *


def keygen():
  print('Generating...')

  dsa = DSA()
  dsa.keygen()

  try:
    f = open(f'dsa_public', 'w')
    f.write(dsa.export_public_key())
    f.close()
  except:
    print('Error. Could not save public key to a file')
    return None

  try:
    f = open(f'dsa_private', 'w')
    f.write(dsa.export_private_key())
    f.close()
  except:
    print('Error. Could not save private key to a file')
    return None
  
  print('Done')


def sign(message_path, key_path):
  dsa = DSA()

  try:
    message_file = open(message_path, 'r')
    message = message_file.read()
    message_file.close()
  except:
    print('Error. Could not open the message file')
    return None

  try:
    key_file = open(key_path, 'r')
    key = dsa.load_private_key(key_file.read())
    key_file.close()
  except:
    print('Error. Unable to load the private key')
    return None

  try:
    signature_file = open(f'signature-{message_path}', 'w')
    signature = dsa.sign(message)
    signature_file.write(signature)
    signature_file.close()
  except:
    print('Error. Unable to generate the signature file')
    return None

  print(f'Message {message_path} signed. Signature saved to signature-{message_path}')


def verify(message_path, key_path):
  dsa = DSA()

  try:
    message_file = open(message_path, 'r')
    message = message_file.read()
    message_file.close()
  except:
    print('Error. Unable to load the signature')
    return None

  try:
    signature_file = open(f'signature-{message_path}', 'r')
    signature = signature_file.read()
    signature_file.close()
  except:
    print('Error. Unable to load the signature')
    return None

  try:
    key_file = open(key_path, 'r')
    key = dsa.load_public_key(key_file.read())
    key_file.close()
  except:
    print('Error. Unable to load the public key')
    return None

  if dsa.verify(message, signature):
    print('Signature is valid')
  else:
    print('The signature is not valid')


if __name__ == '__main__':
  if argv[1] == '--keygen':
    keygen()
  elif argv[1] == '--sign' and argv[2] is not None and argv[3] is not None:
    sign(argv[2], argv[3])
  elif argv[1] == '--verify' and argv[2] is not None and argv[3] is not None:
    verify(argv[2], argv[3])
  else:
    print('Error. Unexpected arguments')

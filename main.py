from sys import argv
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


KEY_SIZE = 2048
SIGNATURE_TYPE = 'fips-186-3'


def keygen():
  print('Generating...')

  key = DSA.generate(KEY_SIZE)

  try:
    f = open(f'dsa_public.pem', 'wb')
    f.write(key.publickey().export_key())
    f.close()
  except:
    print('Error. Could not save public key to a file')

  try:
    f = open(f'dsa_private.pem', 'wb')
    f.write(key.export_key())
    f.close()
  except:
    print('Error. Could not save private key to a file')
  
  print('Done')


def sign(message_path, key_path):
  try:
    message_file = open(message_path, 'rb')
    message = message_file.read()
    message_hash = SHA256.new(message)
    message_file.close()
  except:
    print('Error. Could not open the message file')

  try:
    key_file = open(key_path, 'rb')
    key = DSA.import_key(key_file.read())
    key_file.close()
  except:
    print('Error. Unable to load the private key')

  try:
    signature_file = open(f'signature-{message_path}', 'wb')
    signer = DSS.new(key, SIGNATURE_TYPE)
    signature = signer.sign(message_hash)
    signature_file.write(signature)
    signature_file.close()
  except:
    print('Error. Unable to generate the signature file')

  print(f'Message {message_path} signed. Signature saved to signature-{message_path}')


def verify(message_path, key_path):
  try:
    message_file = open(message_path, 'rb')
    message = message_file.read()
    message_hash = SHA256.new(message)
    message_file.close()
  except:
    print('Error. Unable to load the signature')

  try:
    signature_file = open(f'signature-{message_path}', 'rb')
    signature = signature_file.read()
    signature_file.close()
  except:
    print('Error. Unable to load the signature')

  try:
    key_file = open(key_path, 'rb')
    key = DSA.import_key(key_file.read())
    key_file.close()
  except:
    print('Error. Unable to load the public key')

  try:
    verifier = DSS.new(key, SIGNATURE_TYPE)
    verifier.verify(message_hash, signature)
    
    print('Signature is valid')
  except ValueError:
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

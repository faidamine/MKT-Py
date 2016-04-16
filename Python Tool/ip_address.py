# Importing os
import os
# Method to get the IP Address
def get_ip_address ( url ):
  command = "host " + url
  process = os.popen( command )
  results = str( process.read() )
  marker = results.find( 'has address' ) + 12
# Returning only the top level IP Address
  print("IP Address done!")
  return results[marker:].splitlines()[0]

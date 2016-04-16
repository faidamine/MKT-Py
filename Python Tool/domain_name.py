# Importing get_tld
from tld import get_tld
# Function to get the top level domain
def get_domain_name ( url ):
   domain_name = get_tld(url)
   print("Domain name done!")
   return domain_name

import urllib2
import io


def get_robots_txt( url ):
 if url.endswith( '/' ):
    path = url
 else:
   path = url + "/"
   req = urllib2.urlopen( path + "robots.txt", data = None )
   data = io.TextIOWrapper( req, encoding = 'utf8')
   print("Robots.txt done!")
   return data.read()

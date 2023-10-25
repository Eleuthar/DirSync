from hashlib import md5
from sys import argv
from os import walk, listdir, path, mkdir, replace, remove, rmdir, rename
from shutil import copytree, copy2
from datetime import datetime
from time import sleep
from copy import deepcopy



client = "C:\\Users\\Florin Bujoreanu\\Downloads\\tzt 1"
cloud = "C:\\Users\\Florin Bujoreanu\\Downloads\\tzt 1 - Copy"
client_hexmap = { }
cloud_hexmap = { }
logger = open( "C:\\Users\\Florin Bujoreanu\\OneDrive - IT Teams\\Documents\\dirSync\\logz", 'w' )
interval = 5



def log_it( logger, log_item ):    
    print( log_item )
    logger.write( log_item )	
    return
    
   
def generate_file_hex( root, filename, blocksize=8192 ):
	hh = md5()
	with open( path.join( root, filename ) , "rb" ) as f:
		while buff := f.read( blocksize ):
			hh.update( buff )
	return hh.hexdigest()
    
    
def generate_hexmap( target, logger ):
	hexmap = { 
		'root': [],
		'fname': [], 
		'hex': []
	}
	logger.write( f" {target} HEXMAP ".center (60, "-"))
	for directory in walk( target ):
	# ( 0=dirname, 1=[folders], 2=[files] )   
		# [ len( target ) : ]
		# separate starting from basename	  
		root = directory[0]		
		for fname in directory[2]:
			hexmap[ 'root' ].append( root )
			hexmap[ 'fname' ].append( fname )
			hx = generate_file_hex( root, fname )
			hexmap[ 'hex' ].append( hx )			
			logger.write( root )
			logger.write( fname )
			logger.write( hx )
			logger.write("\n\n{60*'-'}\n\n")			
	return hexmap
    
    
def rename_it( logger, prop, fpath_on_cloud ):	
	global client_hexmap, cloud
	old_path = fpath_on_cloud
	for z in range( len( client_hexmap[ 'hex' ] ) ):					
		if prop == client_hexmap[ 'hex' ][ z ]:			
		# extract the corresponding full path on client side	
			new_fname = client_hexmap[ 'fname' ][ z ]			
			new_root = client_hexmap[ 'root' ][ z ][ len( client ) : ]
			new_path = path.join( cloud, new_root, new_fname )			
			try:
				rename( new_path, old_path )
				log_it( logger, f"Renamed {old_path} to {new_path}\n")
			except Exception as X:
				log_it( logger, f"{X}\n" )
			return
            
            
def rm_obsolete_dir( root, logger ):	  
	try:
		rmdir( root )
		log_it( logger, f"Deleted directory { root }\n" )		
	except Exception as X:
		log_it( logger, f"Error: { X }\n" )	
	return
    

def diff_hex( logger ):	
	# start from the client deepest root	
	# if root not in cloud ['root'], review content recursively to remove\move\keep\update, then add to set for final cleanup	
	global client, cloud, client_hexmap, cloud_hexmap		
	dir_to_rm = set()
	# compare cloud against client
	for hx_tgt in reversed( cloud_hexmap['hex'] ):	
		j = cloud_hexmap['hex'].index( hx_tgt )
		dst_root = cloud_hexmap[ 'root' ][ j ]
		dst_fn = cloud_hexmap[ 'fname' ][ j ] 
		dst_hex = cloud_hexmap[ 'hex' ][ j ]
		fpath_on_cloud = path.join( dst_root, dst_fn )
		# from the landing path point, the file path should be identical for both client & cloud
		# extract with "[ len( cloud ) : ]" the part that cannot be used by target
		# client = C:\Downloads\Pirated_MP3\<common root>
		# cloud = C:\Backup\Pirated_Music\<common root>
		common_root_fn = path.join( dst_root[ len( cloud ) : ], dst_fn )	
		expected_path_on_client = path.join( client, common_root_fn )
		# same hex
		if dst_hex in client_hexmap['hex']:
			# same path > PASS
			if path.exists( expected_path_on_client ):
				log_it( logger, f"PASS { fpath_on_cloud }\n" )
				continue
			# different filename || root || path > RENAME
			else:				
				rename_it( logger, dst_hex, fpath_on_cloud )			
		# no hex match
		else:
			# same path > REPLACED
			if path.exists( expected_path_on_client ):
				log_it( logger, f"UPDATING { fpath_on_cloud }\n" )
				try:					
					remove( fpath_on_cloud )
					copy2( expected_path_on_client, fpath_on_cloud )
					log_it( logger, f"UPDATED { fpath_on_cloud }\n" )
					continue
				except Exception as X:
					log_it( logger,  f"Error: { X }\n" )			
			# same filename but diff root > RENAME
			elif not path.exists( expected_path_on_client ) and dst_fn in client_hexmap['fname']:
				rename_it( logger, dst_root, fpath_on_cloud )				
			# no path match > DELETE
			else:
				try:
					remove( fpath_on_cloud )
				except Exception as X:
					log_it( logger, f"DELETED {fpath_on_cloud}\n")
		if dst_root not in client_hexmap[ 'root' ]:
			dir_to_rm.add( dst_root )
	return dir_to_rm 
    
'''    
for q in range( len(client_hexmap['hex']) ):
    print(client_hexmap['hex'][q])
    print(client_hexmap['fname'][q])
    print(client_hexmap['root'][q])
    print('-------------------------')
'''
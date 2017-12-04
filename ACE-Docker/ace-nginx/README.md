Built on [nginx](https://hub.docker.com/_/nginx/), this image provides an SSL proxy for the [ACE Web Application](https://github.com/Invoke-IR/ACE/tree/master/ACE-WebService). 

ACE relies on SSL for two important features: 
* Encryption - Data sent to and from the ACE Web Application is encrypted
* Authentication - Certificate pinning is used to provide server side authentication to avoid Man-in-the-Middle attacks.

## Using this Image
The ACE Nginx can be run in a couple different ways. 
### Standalone
If you are running ACE in a test/development/standalone deployment, then you can simply run the container as shown below.
```
docker run --name ace-nginx -p 80:80 -p 443:443 -d specterops/ace-nginx
```
### Clustered/Redundant
If you plan on running ACE in a Kubernetes cluster with replication, you want to maintain the same SSL certificates in all instances of the specterops/ace-nginx image. This can be achieved through the use of Volumes. 

Simply create a docker volume (it can be named "certs" or whatever you choose).
```
docker volume create --name certs
```

Then run your container(s) with the -v flag, linking your newly created volume to "/etc/nginx/certs". The volume will ensure a consistent SSL certificate across all ace-nginx instances.
```
docker run --name ace-nginx -v certs:/etc/nginx/certs -p 80:80 -p 443:443 -d specterops/ace-nginx
```

### Get SSL Certificate Thumbprint
The .NET WebClient does not trust self-signed SSL Certificates by default. The ACE PowerShell module bypasses this limitation by using certificate pinning, where the PowerShell script compares the user supplied SSL Thumbprint to that returned by the target server. If the Thumbprints match, then the server is authenticated and the request is allowed. The SSL Thumbprint is output at container runtime and can be found with the following command:
```
docker logs ace-nginx
################################################################
# ACE SSL Thumbprint: 3179CC1A0A0E20477260BFB8D559F35240297E6B #
################################################################
```
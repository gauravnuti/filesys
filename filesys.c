#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include<errno.h>


static int filesys_inited = 0;
char tempkey[keysize];
char qwerty[keysize];
struct mapping merkle_me[numfiles];

struct mnode *make_merkle_tree(int fd1){
	
	struct mnode *root;

	if(filesys_inited==1){		
		int emptyfd=open(merkle_me[fd1].filename, O_RDONLY, S_IRUSR|S_IWUSR);
		int end=lseek(emptyfd, 0, SEEK_END);
		if(end==0){
			////printf("HEREEEEEEEEEEEEEEEEEEEEEEEEE\n");
			root = (struct mnode *)malloc(sizeof(struct mnode));
			memset(root->shaval,0,keysize);
			close(emptyfd);
			strcpy(tempkey, root->shaval);
			root->sibling = NULL;
			root->rightc = NULL;
			root ->leftc = NULL;
			return root;
		}
		close(emptyfd);
	}
	
	int fd;
	if(filesys_inited==0)
		fd=fd1;
	else
		fd=open(merkle_me[fd1].filename, O_RDONLY, S_IRUSR|S_IWUSR);


	int i= -1;
	while(1>0){
		struct mnode *firsi;//first node of this level
		
		if(i==-1){
			////printf("MMT: i==-1\n");
			i = 0;
			char buf[64];
			memset(buf, 0, 64);

			struct mnode *p = (struct mnode *)malloc(sizeof(struct mnode));
			p->sibling = NULL;
			p->leftc = NULL;
			p->rightc = NULL;
		
			firsi = p;			
			struct mnode *j = firsi;
			
			while(read(fd,buf,sizeof(buf))>0){				

				////printf("MMT:read returns=%d, fd=%d, bufer= %s size= %ld \n", sz,fd,buf, sizeof(buf));	
				////printf("REad Error in mmt= %s\n", strerror(errno));
				if(i!=0){
					p = (struct mnode *)malloc(sizeof(struct mnode));
					j->sibling = p;
					j = p;
					p->sibling = NULL;
				}
				p->leftc = NULL;
				p->rightc = NULL;
				get_sha1_hash(buf,64,p->shaval);
				memset(buf, 0, 64);
				////printf("First Level in mmt: hsval=%s\n", p->shaval);
				i+=1;
			}
		}
		else{
			////printf("Watevs =%d\t", i);
			i = 0;
			struct mnode *child = firsi;
			struct mnode *j = NULL;
			struct mnode *p = NULL;
			char buf[40];
			while(1>0){
				
				if(i==0){
					firsi = (struct mnode *)malloc(sizeof(struct mnode));
					p = firsi;
					j=firsi;
					p->sibling = NULL;
				}
				else{
					p = (struct mnode *)malloc(sizeof(struct mnode));
					j->sibling = p;
					j = p;
					p->sibling = NULL;
				}
				
				p->leftc = child;
				p->rightc = child ->sibling;
				strcpy(buf,child->shaval);

				
				if(child->sibling!=NULL){
					strcat(buf,(child->sibling)->shaval);
					////printf("nuti's duffer when sibling is dere%s, %ld\t",buf, strlen(buf) );
					get_sha1_hash(buf, 40, p->shaval);
					memset(buf, 0, 40);
					child = (child->sibling)->sibling;
					i+=1;
					if(child == NULL){
						break;
					}
				////printf("+++++++\t");
				}

				else{
					strcpy(p->shaval,child->shaval);
					memset(buf, 0, 40);
					////printf("nuti's duffer when no sibling %s, %ld\t",buf, strlen(buf) );
					i+=1;
					break;
				}
				////printf("-%d-\t", i);
			}
		}
		if(i == 1){
			int emptyfd;
			if(filesys_inited==0)
				emptyfd=fd1;
			else
				emptyfd=open(merkle_me[fd1].filename, O_RDONLY, S_IRUSR|S_IWUSR);
			int end=lseek(emptyfd, 0, SEEK_END);
			////printf("Root was created with shaval= %s\n", firsi->shaval);
			if(end==0){
				memset(firsi->shaval,0,keysize);
				////printf("MMT: File empty");
				firsi->leftc = NULL;
				firsi->rightc = NULL;
			}
			close(emptyfd);
			
			////printf("Root is created with shaval= %s\n", firsi->shaval);
			strcpy(tempkey, firsi->shaval);
			root = firsi;
			break;
		}
	}
	if(filesys_inited!=0)
		close(fd);
	return root;
}

void delete_merkle_tree(struct mnode *root){
	// if(root->rightc != NULL || root->leftc !=NULL)
	// 			//printf("------More than one node\n");
	// //printf("DELETE WAS INVOKED\n");
	if(root -> rightc == NULL && root->leftc == NULL){
		////printf("DELETE 1\n");
		free(root);
	}
	else{
		if(root -> rightc != NULL){
			////printf("DELETE 2\n");
			delete_merkle_tree(root -> rightc);
		}
		if(root -> leftc != NULL){
			////printf("DELETE 3\n");
			delete_merkle_tree(root -> leftc);
		}
		free(root);
	}
}


int min(int a, int b){
	if(a<b)
		return a;
	else
		return b;
}

int getfree(){
	for(int i=0;i<numfiles;i++){
		if(merkle_me[i].exists==0){
			return i;
		}
	}
	return -1;
	////printf("No more space for files\n");
}

void resetsecure(char *fn){
	int fd = open("secure.txt",O_RDWR,S_IRUSR|S_IWUSR);
	struct mapping checker;
	while(read(fd, &checker, sizeof(struct mapping))>0) {
		if(strcmp(checker.filename,fn) == 0){
			lseek(fd,-1*sizeof(checker),SEEK_CUR);
			memset(checker.shaval,0,keysize);
			write(fd,&checker,sizeof(checker));
			break;
		}
	}
	close(fd);

}

void createsecure(struct mapping fmap){
	int fd = open("secure.txt",O_RDWR,S_IRUSR|S_IWUSR);
	struct mapping checker;
	int flag = 0;
	while(read(fd, &checker, sizeof(struct mapping))>0) {
		if(strcmp(checker.filename,fmap.filename) == 0){
			lseek(fd,-1*sizeof(checker),SEEK_CUR);
			strcpy(checker.shaval, fmap.shaval);
			write(fd,&checker,sizeof(checker));
			flag = 1;
			break;
		}
	}
	if(flag == 0){
		write(fd,&fmap,sizeof(checker));
	}
	close(fd);

}

void updatesecure(struct mapping fmap){
	int fd = open("secure.txt",O_RDWR,S_IRUSR|S_IWUSR);
	struct mapping checker;
	while(read(fd, &checker, sizeof(struct mapping))>0) {
		if(strcmp(checker.filename,fmap.filename) == 0){
			lseek(fd,-1*sizeof(checker),SEEK_CUR);
			strcpy(checker.shaval, fmap.shaval);
			checker.writesz=fmap.writesz;
			write(fd,&checker,sizeof(checker));
			break;
		}
	}
	close(fd);

}

void update_merkle_me(int fd){

}

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);
	struct mapping fmap;
	char fn[60];
	strcpy(fn,pathname);
	int ffd=open (fn, flags, mode);
	if(ffd<0)
		return -1;
	
	//create mapping
	strcpy(fmap.filename, fn);
	fmap.exists = 1;
	merkle_me[ffd] = fmap;	

	//printf("\nsopen 1\n");
	
	if(flags & O_CREAT){
		//printf("sopen CREATE\n");
		//int securefd=open("secure.txt", O_WRONLY | O_APPEND,S_IRUSR|S_IWUSR);
		memset(fmap.shaval,0,keysize);
		fmap.node = (struct mnode *)malloc(sizeof(struct mnode));
		fmap.node->leftc = NULL;
		fmap.node->rightc = NULL;
		fmap.node->sibling = NULL;
		//write(securefd, &fmap, sizeof(struct mapping));
		//close(securefd);
		createsecure(fmap);
		merkle_me[ffd] = fmap;	
		
	}
	else if(flags & O_TRUNC){
		//printf("sopen TRUNC\n");
		resetsecure(fn);
		memset(fmap.shaval,0,keysize);
	}
	else{
		//check integrity
		//printf("Integrity checking\n");
		int flag=check_open_integrity(fn, ffd);
		//printf("Sthng\n");
		if(flag==-1)
			return -1;

		fmap.node=make_merkle_tree(ffd);
		merkle_me[ffd] = fmap;	
		strcpy(merkle_me[ffd].shaval,tempkey);

		//printf("Integrity passed\n");
	}
	//if(merkle_me[ffd].node==NULL)
		//printf("***SOPEN O NO*\n");
	
	//printf("sopen 2\n");
	
	close(ffd);

	
	////pr0intf("sopen 3\n");
	
	int x= open (fn, flags, mode);
	//printf("File descriptor GAIN=%d\n ", x);
	return x;
	//return open(pathname, flags, mode);
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	int fd11 = open("secure.txt",O_RDWR,S_IRUSR|S_IWUSR);
	struct mapping checker;
	while(read(fd11, &checker, sizeof(struct mapping))>0) {
		if(strcmp(checker.filename,merkle_me[fd].filename) == 0){
			lseek(fd,offset,whence);
			return checker.writesz;
		}
	}return -1;
	 
	 
	// ////printf("--------BEGIN WRITE TO %s--with fd= %d-------\n",fmap.filename , fd);
	
	
	// fmap.node=make_merkle_tree(fd);
	// strcpy(fmap.shaval,tempkey);

	// //printf("Calculated val:%s\n",tempkey );
	// int flag=check_integrity(fmap, fd);
	// if(flag==-1){
	// 	//printf("%s\n","Fialing" );
	// 		delete_merkle_tree(fmap.node);
	// 		return -1;
	//  }
	// delete_merkle_tree(fmap.node);


}

int check_integrity_blocks(int fd1, int sz){
	int beg = lseek(fd1, 0, SEEK_CUR);
	int start = beg/64;
	//printf("start block= %d",start);

	int emptyfd=open(merkle_me[fd1].filename, O_RDONLY, S_IRUSR|S_IWUSR);
	int end=lseek(emptyfd, 0, SEEK_END);
	if(end==0){
		char shaval[keysize];
		memset(shaval,0,keysize);
		if(strcmp(shaval, merkle_me[fd1].shaval)!=0){
			close(emptyfd);
			// printf("Read check came here\n");
			return -1;
		}
		close(emptyfd);
		return 0;
	}
	// lseek(emptyfd, 0, SEEK_SET);
	
	int end1 = min(beg+sz,end)/64;
	//printf("end block= %d",end1);
	//end1 = 1;

	lseek(emptyfd,start*64,SEEK_SET);
	struct mnode *startroot = merkle_me[fd1].node;
	struct mnode *newroot = make_merkle_tree(fd1);
	// if(strcmp(startroot->shaval,newroot->shaval)!=0)
	// 	printf("Correct working\n");
	//delete_merkle_tree(newroot);
	//printf("fd to be checked GAIN= %d \n",fd1);

	while(newroot->leftc!=NULL){
		newroot = newroot->leftc;
	}
	while(startroot->leftc!=NULL){
		startroot = startroot->leftc;
	}
	int i = 0;
	//printf("file sz = %d\n", end);
	while(i<start){
		newroot = newroot->sibling;
		startroot = startroot->sibling;	
		i++;
	}
	
	//printf("I came to this part\n");
	// printf("%d no of nodes %d\n", c,128000/64);
	char buf[64];
	memset(buf, 0, 64);
	while(start<=end1 && startroot!=NULL){
		read(emptyfd,buf,sizeof(buf));
		char shaval[keysize];
		memset(shaval,0,keysize);
		get_sha1_hash(buf,64,shaval);
		
		//printf("shaval = %s startroot sha=%s\n",shaval,startroot->shaval );
		shaval[20] = '\0';
	
		
		if(strcmp(shaval, startroot->shaval)!=0){
			close(emptyfd);
			// printf("shaval is %s\n", shaval);
			// printf("startroot is %s\n", startroot->shaval);
			//printf("Read check came here 1\n");
			return -1;
		}
		memset(buf,0,64);
		//printf("Read check came here 2\n");
		startroot = startroot->sibling;	
		start++;
	}
	close(emptyfd);
	return 0;
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
	//printf("I came here\n");
	//if(merkle_me[fd].node==NULL)
		//printf("***O NO SWRITE*\n");
	 
	//struct mapping fmap;
	// strcpy(fmap.filename, merkle_me[fd].filename);
	 
	// ////printf("--------BEGIN WRITE TO %s--with fd= %d-------\n",fmap.filename , fd);
	
	
	// fmap.node=make_merkle_tree(fd);
	// strcpy(fmap.shaval,tempkey);

	
	// int flag=check_integrity(fmap, fd);
	int flag=check_integrity_blocks(fd, count);
	if(flag==-1){
			// delete_merkle_tree(fmap.node);
			return -1;
	 }

	
	 // delete_merkle_tree(fmap.node);

	int ret = write (fd, buf, count); 
	////printf("----------------------------\n");
	//if(merkle_me[fd].node==NULL)
		//printf("***O NO*\n");
	delete_merkle_tree(merkle_me[fd].node);	

	////printf("----------------------------\n");

	merkle_me[fd].node = make_merkle_tree(fd);
	////printf("_____________________Calculated mem key= %s ||\n",merkle_me[fd].shaval);

	strcpy(merkle_me[fd].shaval,tempkey);
	////printf("_____________________Calculated mem key= %s ||\n",merkle_me[fd].shaval);
	
	int temp=lseek(fd,0,SEEK_CUR);
	
	merkle_me[fd].writesz=lseek(fd,0,SEEK_END);
	lseek(fd,temp,SEEK_SET);
	updatesecure(merkle_me[fd]);
	
	//delete_merkle_tree(del);
	 //checkopen();
	 ////printf("--------END OF WRITE------\n");
	return ret;
	//return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	 
	//  struct mapping fmap;
	//  strcpy(fmap.filename, merkle_me[fd].filename);
	 
	// ////printf("--------BEGIN READ TO %s--with fd= %d-------\n",fmap.filename , fd);
	
	// fmap.node=make_merkle_tree(fd);
	// ////printf("SREAD Calculated temp key= %s ||\n",tempkey);
	// strcpy(fmap.shaval,tempkey);
	
	//  int flag=check_integrity(fmap, fd);
	 int flag=check_integrity_blocks(fd, count);
	 if(flag==-1){
	 		//delete_merkle_tree(fmap.node);
	 		//printf("READ came here\n");
	 		return -1;
	 }

	////printf("----------------------------\n");
	//delete_merkle_tree(fmap.node);
	int ret = read (fd, buf, count);

	//  int flag=check_integrity(fmap);
	// if(flag==-1)
	// 		return -1;
	// //printf("file hash = %s\n", fmap.shaval);
	////printf("Returns with val=%d count=%ld\n", ret, count);
	return ret;
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	delete_merkle_tree(merkle_me[fd].node);
	merkle_me[fd].exists=0;
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{	
	setup();
	//printf("fsinit starts\n");
	int securefd=open("secure.txt", O_CREAT|O_RDWR,S_IRUSR|S_IWUSR);
	struct mapping checker;
	struct securelist *llist;
	struct securelist *head=NULL;
	struct securelist *tail;
	int flag=0;
	////printf("Inside filesys init: b4 loop: %ld\n",  sizeof(struct mapping) );
	////printf("fsinit 2\n");
	while(read(securefd, &checker, sizeof(struct mapping))>0) {
		////printf("." );
		flag=check_filesys_integrity(checker);
		if(flag==1) //file doesn't exist, do not rewrite to secure.txt
			flag++;
		else if(flag==-1) //integrity fail
			return 1;
		else{
			//file exists; add to LL
			llist=(struct securelist*)malloc(sizeof(struct securelist));
			llist->node=checker;
			llist->next=NULL;
			if(head==NULL)
			{ 
				head=llist;
				tail=llist;
			}
			else {

				tail->next=llist;
				tail=llist;
			}
		}
	}
	////printf("fsinit 3\n");
	////printf("Inside filesys init: b4 loop\n" );

	while(head!=NULL && flag!=0){
		//Update the secure.txt, without the deleted files
		checker=head->node;
		write(securefd, &checker, sizeof(struct mapping));
		head=head->next;
	}
	

	close(securefd);
	//free(llist);
	filesys_inited = 1;
	//printf("fsinit ends\n");
	return 0;
}

int check_integrity(struct mapping fmap, int fd){
	// //printf("Check integrity: read: Calculated fmap key= %s ||\n",fmap.shaval);
	 ////printf("Check integrity: read: Calculated in memory key= %s ||\n", merkle_me[fd].shaval);
	if(strcmp(fmap.shaval, merkle_me[fd].shaval)!=0)
		return -1;

	return 0;
}

int check_filesys_integrity(struct mapping checker){
	/* returns -1 on failure of integrity
	 * returns 0 on success
	 * returns 1 if file not found
	 */
	////printf("Checkfilesys init called\n");
	char securekey[keysize];
	strcpy(securekey, checker.shaval);
	char shakey[keysize];
	int fd=open(checker.filename, O_RDONLY,0);
	if(fd==-1){ //File Does Not Exist in system
		close(fd);
		return 1;
	} 
	struct mnode * ptr=make_merkle_tree(fd);
	close(fd);
	
	strcpy(shakey,tempkey);
	delete_merkle_tree(ptr);
	////printf("shaval for integrity check= %s and %s\n", shakey, securekey);
	if(strcmp(shakey,securekey)!=0){
		//printf("Checkfilesys init failed\n");
		return -1;
	}
	////printf("Checkfilesys init passed\n");
	return 0;


}

int check_open_integrity(char* file, int fd){ //fd is fd of file about to be open
	/* returns -1 on failure of integrity
	 * returns 0 on success
	 */

	// check with secure.txt

	struct mapping securefmap;
	struct mapping checkme;
	checkme.node=make_merkle_tree(fd);
	////printf("Calculated tempkey= %s ||\n",tempkey);
	strcpy(checkme.shaval, tempkey);
	////printf("Calculated Shaval= %s ||\n",checkme.shaval);

	delete_merkle_tree(checkme.node);
	int securefd=open("secure.txt", O_RDONLY,S_IRUSR|S_IWUSR);

	while(read(securefd, &securefmap, sizeof(struct mapping))>0){
		////printf("Filename for integrity check= %s and %s\n", securefmap.filename, file);
		if(strcmp(securefmap.filename, file)==0){
			////printf("shaval for open integrity check= %s and %s\n", securefmap.shaval, checkme.shaval);
			
			if(strcmp(checkme.shaval,securefmap.shaval)!=0)
				{	//printf("Integrity failed\n");
				return -1;
			}
			break;
		}
	}
	//printf("ret true for integrity");
	return 0;
}

void setup(){
	for(int i=3;i<numfiles;++i)
		merkle_me[i].exists=0;
}


// void checkopen(){
// 	char zerobuf[keysize];
// 	memset(zerobuf,0,keysize);
// 	for(int i=3;i<numfiles;++i)
// 		if(merkle_me[i].exists==1)
// 		{
// 			//printf("Filename: %s Shaval= %s \n", merkle_me[i].filename, merkle_me[i].shaval  );
// 			if(strcmp(merkle_me[i].shaval, zerobuf)==0)
// 				//printf("Shaval Shaval\n");
// 		}

// }

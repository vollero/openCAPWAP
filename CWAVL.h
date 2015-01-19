typedef struct nodeAVL
{
	//WTP: index == BSS index
	//AC: index == WTP index
    int index;
    int radioID;
    unsigned char staAddr[ETH_ALEN];
    unsigned char BSSID[ETH_ALEN];
    //per AC: serve anche radioID?
    struct nodeAVL*  left;
    struct nodeAVL*  right;
    int      height;
} nodeAVL;

extern nodeAVL * avlTree;
extern CWThreadMutex mutexAvlTree;

void AVLdispose(nodeAVL* t);
nodeAVL* AVLfind( unsigned char * staAddr, nodeAVL *t );
nodeAVL* AVLfind_min( nodeAVL *t );
nodeAVL* AVLfind_max( nodeAVL *t );
nodeAVL* AVLinsert( int index, unsigned char * staAddr, unsigned char * BSSID, int radioID, nodeAVL *t );
struct nodeAVL* AVLdeleteNode(struct nodeAVL* root, unsigned char * staAddr, int radioID);
void AVLdisplay_avl(nodeAVL* t);
int AVLget( nodeAVL* n );
int AVLgetBalance(struct nodeAVL *N);
nodeAVL* AVLfindWTPNode(nodeAVL* t, int index);
struct nodeAVL* AVLdeleteNodeWithoutRadioID(struct nodeAVL* root, struct nodeAVL* nodeToDelete);

nodeAVL* AVLsingle_rotate_with_left( nodeAVL* k2 );
nodeAVL* AVLsingle_rotate_with_right( nodeAVL* k2 );
nodeAVL* AVLdouble_rotate_with_left( nodeAVL* k3 );
nodeAVL* AVLdouble_rotate_with_right( nodeAVL* k3 );

int compareEthAddr(unsigned char * staAddr, unsigned char * AVLaddr);

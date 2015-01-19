#include "CWCommon.h"

int compareEthAddr(unsigned char * staAddr, unsigned char * AVLaddr) {
	int index=0;
	for(index=0; index<ETH_ALEN; index++)
	{
		if((int)staAddr[index] > (int)AVLaddr[index])
			return 1;
		if((int)staAddr[index] < (int)AVLaddr[index])
			return -1;
	}
	
	//Gli indirizzi sono uguali
	return 0;
}

/*
    remove all nodes of an AVL tree
*/
void AVLdispose(nodeAVL* t)
{
    if( t != NULL )
    {
        AVLdispose( t->left );
        AVLdispose( t->right );
        free( t );
    }
}

/*
    find a specific nodeAVL's key in the tree
*/
nodeAVL* AVLfind(unsigned char * staAddr, nodeAVL* t )
{
	if(staAddr == NULL || t == NULL )
        return NULL;
        
    if(compareEthAddr(staAddr, t->staAddr) < 0)
        return AVLfind(staAddr, t->left );
    else if(compareEthAddr(staAddr, t->staAddr) > 0)
        return AVLfind(staAddr,  t->right );
    else
        return t;
}

nodeAVL* AVLfindWTPNode(nodeAVL* t, int index)
{
	if(t == NULL)
        return NULL;
        
    if(t->index == index)
		return t;
	
	AVLfindWTPNode(t->left, index);
	AVLfindWTPNode(t->right, index);
	/*
	else if(compareEthAddr(staAddr, t->staAddr) < 0)
        return AVLfindWTPNode(staAddr, t->left, index);
    else if(compareEthAddr(staAddr, t->staAddr) > 0)
        return AVLfindWTPNode(staAddr,  t->right, index);
    else
        return NULL;
	*/
}

/*
    find minimum nodeAVL's key
*/
nodeAVL* AVLfind_min( nodeAVL* t )
{
    if( t == NULL )
        return NULL;
    else if( t->left == NULL )
        return t;
    else
        return AVLfind_min( t->left );
}

/*
    find maximum nodeAVL's key
*/
nodeAVL* AVLfind_max( nodeAVL* t )
{
    if( t != NULL )
        while( t->right != NULL )
            t = t->right;

    return t;
}

/*
    get the height of a nodeAVL
*/
int AVLheight( nodeAVL* n )
{
    if( n == NULL )
        return -1;
    else
        return n->height;
}

/*
    get maximum value of two integers
*/
int AVLmax( int l, int r)
{
    return l > r ? l: r;
}

/*
    perform a rotation between a k2 nodeAVL and its left child

    note: call single_rotate_with_left only if k2 nodeAVL has a left child
*/

nodeAVL* AVLsingle_rotate_with_left( nodeAVL* k2 )
{
    nodeAVL* k1 = NULL;

    k1 = k2->left;
    k2->left = k1->right;
    k1->right = k2;

    k2->height = AVLmax( AVLheight( k2->left ), AVLheight( k2->right ) ) + 1;
    k1->height = AVLmax( AVLheight( k1->left ), k2->height ) + 1;
    return k1; /* new root */
}

/*
    perform a rotation between a nodeAVL (k1) and its right child

    note: call single_rotate_with_right only if
    the k1 nodeAVL has a right child
*/

nodeAVL* AVLsingle_rotate_with_right( nodeAVL* k1 )
{
    nodeAVL* k2;

    k2 = k1->right;
    k1->right = k2->left;
    k2->left = k1;

    k1->height = AVLmax( AVLheight( k1->left ), AVLheight( k1->right ) ) + 1;
    k2->height = AVLmax( AVLheight( k2->right ), k1->height ) + 1;

    return k2;  /* New root */
}

/*

    perform the left-right double rotation,

    note: call double_rotate_with_left only if k3 nodeAVL has
    a left child and k3's left child has a right child
*/

nodeAVL* AVLdouble_rotate_with_left( nodeAVL* k3 )
{
    /* Rotate between k1 and k2 */
    k3->left = AVLsingle_rotate_with_right( k3->left );

    /* Rotate between K3 and k2 */
    return AVLsingle_rotate_with_left( k3 );
}

/*
    perform the right-left double rotation

   notes: call double_rotate_with_right only if k1 has a
   right child and k1's right child has a left child
*/
nodeAVL* AVLdouble_rotate_with_right( nodeAVL* k1 )
{
    /* rotate between K3 and k2 */
    k1->right = AVLsingle_rotate_with_left( k1->right );

    /* rotate between k1 and k2 */
    return AVLsingle_rotate_with_right( k1 );
}

/*
    insert a new nodeAVL into the tree
*/
nodeAVL* AVLinsert(int index, unsigned char * staAddr, unsigned char * BSSID, int radioID, nodeAVL* t )
{
	if(staAddr == NULL)
		return NULL;
		
    if( t == NULL )
    {
        /* Create and return a one-nodeAVL tree */
        t = (nodeAVL*)malloc(sizeof(nodeAVL));
        if( t == NULL )
        {
            CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			return NULL;
        }
        
        t->index = index;
        t->radioID = radioID;
        CW_COPY_MEMORY(t->staAddr, staAddr,ETH_ALEN);
        if(BSSID != NULL)
			 CW_COPY_MEMORY(t->BSSID, BSSID,ETH_ALEN);
			 
        t->height = 0;
        t->left = t->right = NULL;
    }
    else if(compareEthAddr(staAddr, t->staAddr) < 0)
    {
        t->left = AVLinsert(index, staAddr, BSSID, radioID, t->left );
        if( AVLheight( t->left ) - AVLheight( t->right ) == 2 )
            if( compareEthAddr(staAddr, t->left->staAddr) < 0 )
                t = AVLsingle_rotate_with_left( t );
            else
                t = AVLdouble_rotate_with_left( t );
    }
    else if(compareEthAddr(staAddr, t->staAddr) > 0)
    {
        t->right = AVLinsert(index, staAddr, BSSID, radioID, t->right );
        if( AVLheight( t->right ) - AVLheight( t->left ) == 2 )
            if( compareEthAddr(staAddr, t->right->staAddr) > 0)
                t = AVLsingle_rotate_with_right( t );
            else
                t = AVLdouble_rotate_with_right( t );
    }
    /* Else X is in the tree already; we'll do nothing */

    t->height = AVLmax( AVLheight( t->left ), AVLheight( t->right ) ) + 1;
    return t;
}

/* Given a non-empty binary search tree, return the node with minimum
   key value found in that tree. Note that the entire tree does not
   need to be searched. */
struct nodeAVL * AVLminValueNode(struct nodeAVL* node)
{
    struct nodeAVL* current = node;
 
    /* loop down to find the leftmost leaf */
    while (current->left != NULL)
        current = current->left;
 
    return current;
}

struct nodeAVL* AVLdeleteNode(struct nodeAVL* root, unsigned char * staAddr, int radioID)
{
	if(staAddr == NULL)
		return NULL;
    // STEP 1: PERFORM STANDARD BST DELETE
	
    if (root == NULL)
        return root;
 
    // If the key to be deleted is smaller than the root's key,
    // then it lies in left subtree
    if ( compareEthAddr(staAddr, root->staAddr) < 0 )
        root->left = AVLdeleteNode(root->left, staAddr, radioID);
 
    // If the key to be deleted is greater than the root's key,
    // then it lies in right subtree
    else if( compareEthAddr(staAddr, root->staAddr) > 0 )
        root->right = AVLdeleteNode(root->right, staAddr, radioID);
 
    // if key is same as root's key, then This is the node
    // to be deleted. If radioID is the same
    else
    {
		 if(root->radioID == radioID)
		 {
			// node with only one child or no child
			if(
				((root->left == NULL) || (root->right == NULL)) &&
				(root->radioID == radioID)
			)
			{
				struct nodeAVL *temp = root->left ? root->left : root->right;
	 
				// No child case
				if(temp == NULL)
				{
					temp = root;
					root = NULL;
				}
				else // One child case
				 *root = *temp; // Copy the contents of the non-empty child
	 
				free(temp);
				
				CWPrintEthernetAddress(staAddr, "STA deleted from AVL");
			}
			else 
			{
				// node with two children: Get the inorder successor (smallest
				// in the right subtree)
				struct nodeAVL* temp = AVLminValueNode(root->right);
							
				// Copy the inorder successor's data to this node
				root->index = temp->index;
				root->radioID = temp->radioID;
				CW_COPY_MEMORY(root->staAddr, temp->staAddr, ETH_ALEN);
				CW_COPY_MEMORY(root->BSSID, temp->BSSID, ETH_ALEN);
				
				// Delete the inorder successor
				root->right = AVLdeleteNode(root->right, temp->staAddr, temp->radioID);
			}
        }
        else
		{
			CWLog("AVL find STA[%02x:%02x:%02x:%02x:%02x:%02x] node to delete, but radioID value (%d) is different from input radioID(%d). So AVL doesn't delete node", (int)staAddr[0], (int)staAddr[1], (int)staAddr[2], (int)staAddr[3], (int)staAddr[4], (int)staAddr[5],
																																										root->radioID, radioID);
		}
    }
    
    // If the tree had only one node then return
    if (root == NULL)
      return root;
 
    // STEP 2: UPDATE HEIGHT OF THE CURRENT NODE
    root->height = AVLmax(AVLheight(root->left), AVLheight(root->right)) + 1;
 
    // STEP 3: GET THE BALANCE FACTOR OF THIS NODE (to check whether
    //  this node became unbalanced)
    int balance = AVLgetBalance(root);
 
    // If this node becomes unbalanced, then there are 4 cases
 
    // Left Left Case
    if (balance > 1 && AVLgetBalance(root->left) >= 0)
        return AVLsingle_rotate_with_right(root);
 
    // Left Right Case
    if (balance > 1 && AVLgetBalance(root->left) < 0)
    {
        root->left =  AVLsingle_rotate_with_left(root->left);
        return AVLsingle_rotate_with_right(root);
    }
 
    // Right Right Case
    if (balance < -1 && AVLgetBalance(root->right) <= 0)
        return AVLsingle_rotate_with_left(root);
 
    // Right Left Case
    if (balance < -1 && AVLgetBalance(root->right) > 0)
    {
        root->right = AVLsingle_rotate_with_right(root->right);
        return AVLsingle_rotate_with_left(root);
    }
 
    return root;
}

struct nodeAVL* AVLdeleteNodeWithoutRadioID(struct nodeAVL* root, struct nodeAVL* nodeToDelete)
{
	if(nodeToDelete->staAddr == NULL)
		return NULL;
    // STEP 1: PERFORM STANDARD BST DELETE
	
    if (root == NULL)
        return root;
 
    // If the key to be deleted is smaller than the root's key,
    // then it lies in left subtree
    if ( compareEthAddr(nodeToDelete->staAddr, root->staAddr) < 0 )
        root->left = AVLdeleteNodeWithoutRadioID(root->left, nodeToDelete);
 
    // If the key to be deleted is greater than the root's key,
    // then it lies in right subtree
    else if( compareEthAddr(nodeToDelete->staAddr, root->staAddr) > 0 )
        root->right = AVLdeleteNodeWithoutRadioID(root->right, nodeToDelete);
 
    // if key is same as root's key, then This is the node
    // to be deleted. If radioID is the same
    else
    {
		// node with only one child or no child
		if((root->left == NULL) || (root->right == NULL))
		{
				struct nodeAVL *temp = root->left ? root->left : root->right;
				CWPrintEthernetAddress(root->staAddr, "Delete STA from AVL");
				// No child case
				if(temp == NULL)
				{
					temp = root;
					root = NULL;
				}
				else // One child case
				{
					*root = *temp; // Copy the contents of the non-empty child
				}

				free(temp);
				
				temp = NULL;			
		}
		else 
		{
				// node with two children: Get the inorder successor (smallest
				// in the right subtree)
				struct nodeAVL* temp = AVLminValueNode(root->right);
				
				CWPrintEthernetAddress(root->staAddr, "Removing STA from AVL");

				// Copy the inorder successor's data to this node
				root->index = temp->index;
				root->radioID = temp->radioID;
				CW_COPY_MEMORY(root->staAddr, temp->staAddr, ETH_ALEN);
				CW_COPY_MEMORY(root->BSSID, temp->BSSID, ETH_ALEN);
				
				CWPrintEthernetAddress(temp->staAddr, "Node to move");

				// Delete the inorder successor
				root->right = AVLdeleteNodeWithoutRadioID(root->right, temp);
		}
    }
    
    // If the tree had only one node then return
    if (root == NULL)
      return root;

	CWLog("root != NULL");
 
    // STEP 2: UPDATE HEIGHT OF THE CURRENT NODE
    root->height = AVLmax(AVLheight(root->left), AVLheight(root->right)) + 1;
 
    // STEP 3: GET THE BALANCE FACTOR OF THIS NODE (to check whether
    //  this node became unbalanced)
    int balance = AVLgetBalance(root);
 
    // If this node becomes unbalanced, then there are 4 cases
 
    // Left Left Case
    if (balance > 1 && AVLgetBalance(root->left) >= 0)
        return AVLsingle_rotate_with_right(root);
 
    // Left Right Case
    if (balance > 1 && AVLgetBalance(root->left) < 0)
    {
        root->left =  AVLsingle_rotate_with_left(root->left);
        return AVLsingle_rotate_with_right(root);
    }
 
    // Right Right Case
    if (balance < -1 && AVLgetBalance(root->right) <= 0)
        return AVLsingle_rotate_with_left(root);
 
    // Right Left Case
    if (balance < -1 && AVLgetBalance(root->right) > 0)
    {
        root->right = AVLsingle_rotate_with_right(root->right);
        return AVLsingle_rotate_with_left(root);
    }
 
    return root;
}

/*
    data data of a nodeAVL
*/
/*
int get(nodeAVL* n)
{
    return n->data;
}
*/

// Get Balance factor of node N
int AVLgetBalance(struct nodeAVL *N)
{
    if (N == NULL)
        return 0;
    return AVLheight(N->left) - AVLheight(N->right);
}

/*
    Recursively display AVL tree or subtree
*/
void AVLdisplay_avl(nodeAVL* t)
{
    if (t == NULL)
        return;
    CWLog("[%d] - %02x:%02x:%02x:%02x:%02x:%02x",t->index, (int)t->staAddr[0], (int)t->staAddr[1], (int)t->staAddr[2], (int)t->staAddr[3], (int)t->staAddr[4], (int)t->staAddr[5]);

    if(t->left != NULL)
		CWLog("[L: %d] - %02x:%02x:%02x:%02x:%02x:%02x",t->left->index, (int)t->left->staAddr[0], (int)t->left->staAddr[1], (int)t->left->staAddr[2], (int)t->left->staAddr[3], (int)t->left->staAddr[4], (int)t->left->staAddr[5]);
    if(t->right != NULL)
		CWLog("[R: %d] - %02x:%02x:%02x:%02x:%02x:%02x",t->right->index, (int)t->right->staAddr[0], (int)t->right->staAddr[1], (int)t->right->staAddr[2], (int)t->right->staAddr[3], (int)t->right->staAddr[4], (int)t->right->staAddr[5]);

    CWLog("\n");

    AVLdisplay_avl(t->left);
    AVLdisplay_avl(t->right);
}

/*
nodeAVL * AVLremoveWTP(nodeAVL* root, int WTPIndex)
{
    if (root == NULL)
        return NULL;
    
    while(root != NULL)
    {
		if(root->index == WTPIndex)
		AVLdeleteNode(struct nodeAVL* root, unsigned char * staAddr, int radioID)
			
	}
    CWLog("[%d] - %02x:%02x:%02x:%02x:%02x:%02x",t->index, (int)t->staAddr[0], (int)t->staAddr[1], (int)t->staAddr[2], (int)t->staAddr[3], (int)t->staAddr[4], (int)t->staAddr[5]);

    if(t->left != NULL)
		CWLog("[L: %d] - %02x:%02x:%02x:%02x:%02x:%02x",t->left->index, (int)t->left->staAddr[0], (int)t->left->staAddr[1], (int)t->left->staAddr[2], (int)t->left->staAddr[3], (int)t->left->staAddr[4], (int)t->left->staAddr[5]);
    if(t->right != NULL)
		CWLog("[R: %d] - %02x:%02x:%02x:%02x:%02x:%02x",t->right->index, (int)t->right->staAddr[0], (int)t->right->staAddr[1], (int)t->right->staAddr[2], (int)t->right->staAddr[3], (int)t->right->staAddr[4], (int)t->right->staAddr[5]);

    CWLog("\n");

    AVLdisplay_avl(t->left);
    AVLdisplay_avl(t->right);
}
*/

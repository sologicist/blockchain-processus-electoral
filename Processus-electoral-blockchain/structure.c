#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "structure.h"
#include "chiffrement.h"
#include "struct.h"
#include <math.h>
#include <assert.h>


/* == 3.2 == :
initialisation d'une clé
*/

void init_key(Key* key, long val, long n){
    key->val=val;
    key->n=n;
}

/* == 3.3 == :
Uyilise le protocole RSA pour initialisée une clé 
publique et une privée (déja allouée)
*/

void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size){
    //Generation de cle :
    long p =random_prime_number(low_size, up_size, 5000);
    long q =random_prime_number(low_size, up_size, 5000);
    while (p == q){
        q =random_prime_number(2, 7, 5000);
    }
    long n, s, u;
    generate_keys_values(p, q, &n, &s, &u);
    //Pour avoir des cles positives :
    if (u < 0){
        long t=(p-1)*(q-1);
        u=u+t ; //on aura toujours s*u mod t = 1
    }

    pKey->val=s;
    pKey->n=n;

    sKey->val=u;
    sKey->n=n;
}

void print_list_keys(CellKey* LCK){
    //affichage de la liste de clés
    CellKey *cour = LCK;

    if (!LCK)
        return;

    while(cour){
        char *tmp = key_to_str(cour->data);
        printf(" %s \n", tmp);
        free(tmp);
        cour=cour->next;
    }
}

/* == 3.6 == :
Alloue et initialise la signature avec un tableau deja
alloue
*/

Signature* init_signature(long* content, int size){
    //initialisation d'une structure Signature
    Signature *sign=(Signature *)malloc(sizeof(Signature));
    assert(sign); 
    sign->size=size; 
    sign->content=content;

    return sign;
}

/* == 3.10 == :
Allocation et initialisation d'une <Protected>
*/

Protected* init_protected(Key* pKey, char* mess, Signature* sgn){
    Protected *pcd=(Protected *)malloc(sizeof(Protected));
    assert(pcd);
    pcd->pKey = pKey;
    pcd->mess = strdup(mess);
    pcd->sgn = sgn;

    return pcd;
}

CellKey* create_cell_key(Key* key){
    //creation d'une cellule de liste chainée comprenant une clé
    CellKey *ck =(CellKey *)malloc(sizeof(CellKey));

    ck->data = key;
    ck->next = NULL;

    return ck;
}

CellKey* ajout_en_tete_CellKey(CellKey* cellkey, Key* key){
    if (!cellkey->data) // si liste vide renvoie une cellule avec la clé
        return create_cell_key(key);
    
    CellKey* ck = create_cell_key(key);
    ck->next = cellkey; // ajout en tete de liste via reconsitution du chainage à l'aide du champs next
    return ck;
}

void delete_cell_key(CellKey* c){
    // test si les structures de sont pas deja vide sinon les free()
    if (!c)
        return;

    if(!c->data)
        free(c);

    free(c->data);
    free(c);
}

void delete_list_keys(CellKey* c){
    CellKey *temp = c;
    // test si les structures de sont pas deja vide sinon les free() en parcourant la liste chainée de clé
    // à l'aide de la fct delete_cell_key()

    if(!c)
        return;

    while (c){
        temp=c->next;
        delete_cell_key(c);
        c=temp;
    }
}

/* == 3.4 == :
key_to_str() retourne une chaîne de caractère representant une clé
str_to_key() retourne une cle representant une chaîne de caractère
*/

char* key_to_str(Key* key){
    if (!key->val || !key->n)
        return "Clé vide";
    
    char *c = malloc(sizeof(char)*20);
    // INSERE LES VALEURS DE LA CLE DANS LA CHAINE : 
    sprintf(c, "(%lx,%lx)", key->val, key->n);
    c[strlen(c)] = '\0';
    
    return c;
}

Key* str_to_key(char* str){
    Key* key=(Key*)malloc(sizeof(Key));
    assert(key);
    // INSERE LES VALEURS DE LA CHAINE DANS LA CLE (si possible)
    if (sscanf(str, "(%lx,%lx)", &key->val, &key->n) == 2){
        return key;
    }
    return NULL;
}


/* == 3.8 == :
Fonctions fournies qui permettent le passage d'une signature
a sa representation en chaine de caracteres et inversement
*/
char *signature_to_str(Signature *sgn){
    char *result=malloc(10*sgn->size*sizeof(char));
    result[0]= '#';
    int pos = 1;
    char buffer[156];
    for (int i=0; i<sgn->size; i++) {
        sprintf(buffer, "%lx", sgn->content[i]);
        for (int j=0; j <strlen(buffer); j++) {
            result[pos] = buffer[j];
            pos = pos+1;
        }
    result[pos]= '#';
    pos = pos+1;
    }
    result[pos] = '\0';
    result = realloc(result,(pos+1)*sizeof(char));
    return result;
}

Signature *str_to_signature(char * str){
    int len = strlen(str);
    long *content =(long*)malloc(sizeof(long)*len);
    int num = 0;
    char buffer[256];
    int pos = 0;
    for (int i=0; i<len; i++) {
        if (str[i] != '#') {
            buffer[pos] = str[i];
            pos = pos+1;
        } else {
            if (pos != 0) {
                buffer[pos] = '\0';
                sscanf(buffer, "%lx",&(content[num]));
                num = num+1;
                pos = 0;
            }
        }
    }
    content = realloc(content, num*sizeof(long));
    return init_signature(content, num);
}

/* == 3.12 == :
Fonctions qui permettent le passage d'un <Protected>
a sa representation en chaine de caracteres et inversement
*/

char *protected_to_str(Protected *pr){

    if(!pr)
        return "vide";

    char *result=malloc(sizeof(char)*100);
    assert(result);

    char* tmp;
    tmp = key_to_str(pr->pKey);
    strcpy(result, tmp); //strcpy pour le premier elem puis strcat pour concatener les elems, séparés par un espace
    strcat(result, " ");
    free(tmp);

    tmp = strdup(pr->mess);
    strcat(result, tmp);
    strcat(result, " ");
    free(tmp);
    
    tmp = signature_to_str(pr->sgn);
    strcat(result, tmp);
    free(tmp);
    
    return result;
}

Protected* str_to_protected(char *str){
    char buffer_cle[100];
    char buffer_msg[256];
    char buffer_sgn[256];

    if (sscanf(str, " %s %s %s\n", buffer_cle, buffer_msg, buffer_sgn) == 3){// test du nombre d'arg recupéré
        // recuperation des valeur des clés et signature à l'aide des fct str to key et str to signature
        // et initialisation d'un protected
        
        Key *key = str_to_key(buffer_cle); 
        Signature * sgn = str_to_signature(buffer_sgn);
        
        return init_protected(key, buffer_msg, sgn);
    }
    return NULL;
}

char* block_to_str(Block* block){
    //transformation d'un block en chaine de char par concatenation
    char* strblock = (char *)malloc(sizeof(char)*1000);
    char* tmp = key_to_str(block->author); //concatenation de l'auteur
    strcpy(strblock, tmp);
    free(tmp);
    strcat(strblock, " ");
    strcat(strblock, block->previous_hash); //concatenation du prev_hash
    
    strcat(strblock, " ");
    
    CellProtected *it = block->votes;
    while(it){ // parcours de la liste chainée de declaratrion et les concatener à la chiane resultat

        char *pr = protected_to_str(it->data);
        strcat(strblock, pr);
        strcat(strblock, " ");
        free(pr);
        it = it->next;
    }

    char *c = malloc(sizeof(char)*10);
    sprintf(c, "%d\0", block->nonce); //concatenation du nonce
    strcat(strblock, c);
    
    
    return strblock;
}

CellProtected* create_cell_protected(Protected* pr){
    // cree et initialise une struct cellProtected 
    CellProtected *cellpr = (CellProtected *)malloc(sizeof(CellProtected));
    cellpr->data=pr;
    cellpr->next=NULL;
    return cellpr;    
    
}

CellProtected* ajout_en_tete_CellPR(CellProtected *cellpr, Protected *pr){
    // test d'abord si les arg ne sont pas null
    if (!cellpr->data)
        return create_cell_protected(pr);

    if(!pr)
        return NULL;
    
    // cree une cellule puis reconstitue la chaine avec le nouvel elem en tete
    CellProtected *cp = create_cell_protected(pr);
    cp->next = cellpr;
    cellpr=cp;

    return cellpr;
}

void afficher_cellPR(CellProtected* cellpr){
    CellProtected *cour = cellpr;
    
    if (!cellpr->data){ // test si la liste est vide
        printf("Liste vide\n");
        return;
    }

    while (cour){// parcours de la liste chainée
        char *tmp = protected_to_str(cour->data);
        printf(" %s\n", tmp);
        free(tmp);
        cour=cour->next;
    }
}

void delete_cell_protected(CellProtected* c){
    if (!c)
        return;
    // liberation de tous les champs d'un protected
    free(c->data->pKey);
    free(c->data->mess);
    free(c->data->sgn->content);
    free(c->data->sgn);
    free(c->data);
    free(c);
    
}

void delete_list_protected(CellProtected* c){
    CellProtected *temp = c;
    if(!c->data){ // test si la liste n'est pas deja vide
        printf("Liste vide\n");
        return;
    }
    while (c){ // parcours pour la supp de chaque element
        temp=c->next;
        delete_cell_protected(c);
        c=temp;
    }
}

void delete_fraud_list_protected(CellProtected** c){
    CellProtected *cour = *c;
    CellProtected *temp;
    CellProtected *prec;

    if (verify(cour->data)==0){ // condition pour la suppression du premier element si verify retourne 0 donc fraude reperé
        temp = cour->next;
        delete_cell_protected(cour);
        cour=temp;
        *c=cour;
    }
        
    while (cour->next){ // parcours pour test les elems suivants
        if (verify(cour->data)==0){
            prec->next = cour->next; // sauvegarde du maillon precedent 
            delete_cell_protected(cour); // suppresion du maillon
            cour=prec->next; // reconstitution de la chaine
        } else {
            prec=cour;    
            cour=cour->next;
        }
    }

    if (verify(cour->data) == 0){ // condition pour la suppression du dernier element
        delete_cell_protected(cour);
    }

}

HashCell* create_hashcell(Key* key){
    //création de la structure Hashcell
    HashCell *h = (HashCell*)malloc(sizeof(HashCell));
    h->key = key;
    h->val = 0;

    return h;
}

int find_position(HashTable* t, Key* key){

    int pos = hash_function(key, t->size); // recuperation de la positon de la clé en arg via la fct de hachage
    char *cle = key_to_str(key);
    
    char *res = key_to_str(t->tab[pos]->key); // verifie d'abord si la clé n'est pas à sa reelle position
    if (strcmp(res, cle) == 0){
        free(res);
        return pos;
    }
    free(res);

    for(int i=pos; i<t->size; i++){ // sinon parcours les elements suivants car probing lineaire
        char *res = key_to_str(t->tab[i]->key);
        if (strcmp(res, cle) == 0){ // comparaison des clés
            free(res);
            return i;
        }
        free(res);
    }

    for(int i=0; i<pos; i++){ // si la clé n'est pas trouvé dans les elem suivants alors on commence du debut de la table
    // jusqu'a la sa reelle position
        char *res = key_to_str(t->tab[i]->key);
        if (strcmp(res, cle) == 0){ // comparaison des clés
            free(res);
            return i;
        }

        free(res);
    }

    free(cle);
    
    return pos; 
}

HashTable* create_hashtable(CellKey* keys, int size){
    HashTable *t = (HashTable*)malloc(sizeof(HashTable));
    t->tab = (HashCell**)malloc(sizeof(HashCell*)*size);
    t->size=size;
    
    for(int i=0; i<t->size; i++){
        t->tab[i]=create_hashcell(NULL); // allooue chaque case du tableau
    }
    int i = 0;
    while(keys && i<size){
        int pos = hash_function(keys->data, size); //récuperation de la position
      
        if( !t->tab[pos]->key ){
            t->tab[pos]->key = keys->data;
        
        }else{
            while(pos>=0){ //parcours du tableau pour repositionner l'element sur les cases suivantes ou precendentes si toutes les cases 
            // suivantes sont prises
                if(pos == size)
                    pos=0;

                if( !t->tab[pos]->key){  
                    t->tab[pos]->key = keys->data;
                    break;
                }

                pos++;
            }   
        }
        i++;
        keys=keys->next;
    }
    return t;
}

void delete_hashtable(HashTable* t){
    // suppression des champs d'une table de hachage
    for(int i; i<t->size; i++){
        free(t->tab[i]);       
    }

    free(t->tab); //supp du pointeur vers tableau de Hashcell
    free(t); // supp de hashtable
}

void delete_block(Block* b){ 
    // free() de tous les champs du block sans supprimer les declarations signée "protected" mais seulemnt la structure de 
    // liste chainée qui les stock
    free(b->hash);
    free(b->previous_hash);
    CellProtected *tmp = b->votes;
    while(b->votes){ // parcours de la liste de vote
        tmp=b->votes->next;
        free(b->votes);
        b->votes=tmp;
    }
}


CellTree* create_node(Block* b){
    // creation d'un noeud 
    CellTree *node = (CellTree *)malloc(sizeof(CellTree));
    node->block = b; 
    node->father = NULL;
    node->firstChild = NULL;
    node->nextBro = NULL;
    node->height = 0;

    return node;
}

int update_height(CellTree* father, CellTree* child){
    if (child->height >= father->height){
        father->height = child->height+1; // compare la taille d'un noeud pere avec son noeud fils
        // si le fils est plus grand ou egale aors on incremente la taille du pere de 1
        return 1;
    }
    return 0;
}

void add_child(CellTree* father, CellTree* child){

    if(!father || !father->block){ // test si arbre vide, si oui le crée
        father = create_node(child->block);
        return;
    }
    

    CellTree *debut=father; 
    if (!father->firstChild){ // test si le noeud n'a pas de fils
        father->firstChild = child;
        child->block->previous_hash = father->block->hash;
        child->father=father;
        
        CellTree *it = father;
        CellTree *itsuiv = child;

        while(it){// update de la taille des noeuds
            update_height(it, itsuiv);
            it=it->father;
            itsuiv=itsuiv->father;
        }
        father=debut;
        return;
    }

    CellTree *it = father->firstChild;
    while(it->nextBro){
            it=it->nextBro;
    }
    it->nextBro = child;
    child->block->previous_hash = father->block->hash;
    child->father=father;
    
    CellTree *itr = father;
    CellTree *itrsuiv = child;
    while(itr){
        update_height(father, child);
        itr=itr->father;
        itrsuiv=itrsuiv->father;
    }

    father=debut;
}

void print_tree(CellTree* node){
    //verifie qu'il existe
    if(!node || !node->block){
        printf("Arbre vide\n");
        return;
    }

    //affchage de la hauteur et des id du bloc 
    printf("hauteur : %d\n", node->height);
    printf("hash : %s\n", node->block->hash);
    printf("previous_hash : %s\n", node->block->previous_hash);
    printf("\n");

    //parcours de l'arbre de maniere recursive
    CellTree *cour=node->firstChild;
    while(cour){
        print_tree(cour);
        cour=cour->nextBro;
    }   
}

void delete_node(CellTree* node){
    if (node->block)
        delete_block(node->block);
    //test si les elements exitent, si oui, les free()
    if(node->father)
        free(node->father);
    if(node->firstChild)
        free(node->firstChild);
    if(node->nextBro)
        free(node->nextBro);
    
    free(node); //free de la tete
}

void delete_tree(CellTree* node){
    if(!node->block){
        free(node);
        printf("Arbre vide\n");
        return;
    }

    CellTree *cour=node->firstChild;
    //parcours de l'arbre de maniere recursive avec appel de delete_node() sur chaque noeud
    while(cour){
        if(!cour->nextBro){
            delete_node(cour); 
            return;
        }
            
        delete_tree(cour);
        cour=cour->nextBro;
    }
}


CellTree* highest_child(CellTree* cell){
    int max = 0;
    CellTree *hchild = malloc(sizeof(CellTree));

    CellTree *node = cell->firstChild;
    while(node){ //parcours des fils pour avoir celui dont la hauteur est la plus longue 
        if(max <= node->height){
            max = node->height;
            hchild = node;
        }
        node = node->nextBro;
    }

    return hchild;
}

CellTree* last_node(CellTree* tree){
    // on test d'abord si l'arbre n'est pas vide ou si il n'a pas de fils donc c'est lui le denier
    if(!tree){
        return NULL;
    }
    if(!tree->block){
        return NULL;
    }

    if(!tree->firstChild){
        return tree;
    }
    CellTree *tmp = highest_child(tree); //recuperation du fils le plus grand
    
    while(tmp->firstChild){ //iterer les petits fils jusqu'à trouver le denier de la chaine de fils la plus longue
        free(tmp);
        tmp = highest_child(tmp);
    }
    return tmp;
}

CellProtected *fusion(CellProtected *liste1, CellProtected* liste2){
    // si l'une est vide on retourne l'autre
    if(!liste1)
        return liste2;
    if(!liste2){
        return liste1;
    }

    // on atteint le dernier element de la premier liste pour y fixer le premier elem de la liste 2 (pointeur vers pointeur)
    CellProtected *debut = liste1;
    while(liste1->next){
        liste1=liste1->next;
    }

    liste1->next = liste2;
    liste1=debut;
    return liste1; // retourne la tete de liste1

    //8.8) Pour cela il faudrait rajouter un champs 
    // dernier_element dans la structure CellProtected

}

CellProtected *fusion_decl(CellTree *tree){
    if(!tree || !tree->block){
        return NULL;
    }
    
    CellProtected *res = (CellProtected *)malloc(sizeof(CellProtected));
    res=tree->block->votes; // recuêration des décla de la racine

    if(!tree->firstChild)
        return res;

    CellTree *tmp = highest_child(tree);
    while(tmp->firstChild){ // puis parcours des fils de la plus longue chiane
    // afin d'accumuler les declaration par fuision de celles ci à la liste res
        res=fusion(res, tmp->block->votes);
        tmp=highest_child(tmp);
    } 
    res=fusion(res, tmp->block->votes);
    return res;
}

int verify_block(Block* b, int d){
    // retourne 1 si le block est valide, 0 sinon
    char* block;
    unsigned char *tmp;
    block = block_to_str(b); // recuperation de l'identifiant du block à partir des informatons du bloc (dont la preuve de travail)
    //afin de verifier qu'il y'a bien d 0
    tmp = str_to_hash(block);
 
    for (int i = 0; i<d; i++){
        if(tmp[i] != '0'){
            return 0;
        }
    }
    return 1; // si bloc valide retourne 1
}

/* == 3.11 == :
Verifie que la signature dans pr correspond au message
et a la personne dans pr
*/
int verify(Protected* pr){
    // decryptage du contenu dans la signature 
    char *tmp = decrypt(pr->sgn->content, pr->sgn->size, pr->pKey->val, pr->pKey->n);

    // comparaison avec le message dans pr 
    if (strcmp(tmp, pr->mess) != 0)
        return 0;
    
    free(tmp);
    return 1;
}
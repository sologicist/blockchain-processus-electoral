#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "structure.h"
#include "chiffrement.h"
#include "readwrite.h"
#include "compute.h"
#include <math.h>
#include <assert.h>


Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV){

    // création des tables hachages pour faciliter la manipulation des données 
    HashTable *Hc= create_hashtable(candidates, sizeC);
    HashTable *Hv = create_hashtable(voters, sizeV);
    int posV = 0;
    int posC = 0;
    int estVotant = -1;
    int max = 0;
    Key* GG=(Key*)malloc(sizeof(Key)); 

    // test si la personne est dans Hv à l'aide du champs val
    // test si le message represente bien un candidat dans Hv
    // ++ valeur de la cellule de la table de Hc 
    while(decl){ // parcours de la liste de declarations et compare la liste de votant avec celle des declarations 
        posV = find_position(Hv, decl->data->pKey); // récupération de la position du votant dans la TdH
        char *cle1 = key_to_str(decl->data->pKey);
        char *cle2 = key_to_str(Hv->tab[posV]->key);
        
        if(strcmp(cle1, cle2) == 0){ // et verification avec la declaration de vote signée
            
            if(Hv->tab[posV]->val == 0){
                Hv->tab[posV]->val++; // si il est verifié alors on incremente de 1 
                estVotant++; // et devient susceptible de voter
            }
        }
        
        free(cle2);
        free(cle1);
    
        if(estVotant >=0 && Hv->tab[posV]->val == 1){ //1 si il peut voter, 2 si il a voté
            Key *cand = str_to_key(decl->data->mess);
            posC = find_position(Hc, cand); // récupération de la position du candidat dans la TdH
            char *cle3 = key_to_str(Hc->tab[posC]->key); //recupere le candidat dans la table de hachage des candidats
            if(strcmp(decl->data->mess, cle3) == 0){ // et verifie avec la declaration de vote signée
                Hc->tab[posC]->val++; // +1 vote pour le candidat
                Hv->tab[posV]->val++; // +1 = 2 donc à voté et ne peut plus voté
            }
                
            free(cle3);
            free(cand);
            estVotant = -1;
        }

        decl = decl->next;
    }

    for(int posi = 0; posi<Hc->size; posi++){ // désignation du vainqueur par comparaison du champs val
        if(Hc->tab[posi]->val > max){
            max = Hc->tab[posi]->val;
            GG = Hc->tab[posi]->key;
        }
    }

    

    // free Hv et Hc
    delete_hashtable(Hv);
    delete_hashtable(Hc);

    return GG;

}

void compute_proof_of_work(Block *B, int d){
    B->nonce = 0;
    int valide = 0;
    char* block;
    unsigned char *tmp;
    while(B->nonce >= 0){ // boucle sans condition
        block = block_to_str(B); 
        tmp = str_to_hash(block); // creation de l'identifiant du block à chaque tour puis test des d premiers chiffres
        for (int i = 0; i<d; i++){
            if(tmp[i] != '0'){
                valide++;
                B->nonce++; // incrémentation du nonce à chaque tour (preuve de travail)
                break;
            }
        }

        if(valide == 0){
            free(block); // si valide on sort de la boucle
            break;
        }
        
        valide = 0;
    }
    
    /*
    for (int it = 0; it<SHA256_DIGEST_LENGTH; it++)
        printf("%c", tmp[it]);
    putchar('\n');
    */
    
}

Key* compute_winner_BT(CellTree* tree, CellKey* candidates, CellKey* voters, int sizeC, int sizeV){
    CellProtected *liste = fusion_decl(tree); // récupération puis fusion de toutes les déclarations composant l'arbre
    
    delete_fraud_list_protected(&liste); // suppression des déclaration frauduleuse
    Key *gg = compute_winner(liste, candidates, voters, sizeC, sizeV); // calcul du vainqueur
    delete_cell_protected(liste);
    
    return gg;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "structure.h"
#include "chiffrement.h"
#include "readwrite.h"
#include "compute.h"
#include "struct.h"
#include <math.h>
#include <assert.h>
#include <dirent.h>


CellKey *read_public_keys(char *nomFic){
    FILE *f = fopen(nomFic, "r");
    if (f == NULL){ // test de l'ouverture du fichier
        printf("Erreur : ouverture fichier\n");
        return NULL;
    }
    char buffer[100];
    CellKey* ck;
    ck=create_cell_key(NULL); //creation de la liste de clé
    char str[100];
    while(fgets(buffer, 100, f)){
        if (sscanf(buffer, " %s\n", str)==1){
            Key *k =  str_to_key(str);
            ck = ajout_en_tete_CellKey(ck, k); // lecture puis ajout en tete de liste
        }
    }
    return ck;
}

CellProtected *read_protected(char *nomFichier){
    FILE *f = fopen(nomFichier, "r");
    if (f == NULL){ // test de l'ouverture du fichier
        printf("Erreur : ouverture fichier\n");
        return NULL;
    }
    char buffer[256];
    CellProtected *cellpr = create_cell_protected(NULL);
    while(fgets(buffer, 256, f)){
        Protected * pr = str_to_protected(buffer);
        cellpr = ajout_en_tete_CellPR(cellpr, pr); // lecture puis ajout en tete de liste
    }
    fclose(f);
    return cellpr;
}

/* == 4.1 == :
Genere 3 fichiers :
- "KEYS.TXT" contient des couples de cles generes aleatoirement
representant les citoyens (publique, privee)
- "CANDIDATES.TXT " contient les cles publiques de citoyens sele-
ctionnes aleatoirement parmi ceux de "KEYS.TXT" : ce seront les candidats
- "DECLARATIONS.TXT" contient les declarations signees pour chaque citoyen
(avec un candidat choisi au hasard par la liste de candidats)
*/

void generate_random_data(int nv, int nc){

    Key *pKey = NULL;
    Key *sKey = NULL; 

    FILE *f = fopen("Keys.txt", "w");
    assert(f); // test de l'ouverture du fichier

    // on genere des cles et on ajoute leur representation caractere dans le fichier <keys.txt>
    for (int i=0; i<nv; i++){
        pKey = (Key*)malloc(sizeof(Key));
        sKey = (Key*)malloc(sizeof(Key)); 
        init_pair_keys(pKey, sKey, 3, 7); // génération de clés
        char *p = key_to_str(pKey);
        char *s = key_to_str(sKey);
        fprintf(f, "%s %s\n", p, s); // écriture de ces clés dans le fichier, une clé par ligne
        free(pKey);
        free(sKey);
        free(p); free(s);
    }
    fclose(f);

    // RECUPERE les cles publiques dans le fichier Keys 
    // et les ajoute dans le fichier CANDIDATES

    FILE *fk = fopen("Keys.txt", "r");
    FILE *fc = fopen("Candidates.txt", "w");
    assert(fk);
    assert(fc);

    char **tabCandidats = (char**)malloc(sizeof(char*)*nc);
    for (int i =0; i<nc; i++){
        tabCandidats[i]=malloc(sizeof(char)); //création d'un tableau de candidats pour le choix aléatoire des candidats
    }

    char buffer[100];
    char str[100];
    int it = 0;
    int irand;
    int *tabRand = (int*)malloc(sizeof(int)*nc);
    int itr = 0;
    int estDedans = 0;

    while(it<nc){ // manipualtion des tableau stockant des nb aléatoire tous differents : represente les lignes choisies
    // nc nombres aléatoire donc nc lignes differentes pour prélever les clés qui deviendront candidats 
        irand = rand() % nv;
        while(itr<it){
            if(tabRand[itr] == irand){
                estDedans++;
                break;
            }
            itr++;
        }
        if(estDedans == 0){ // test si nb deja present dans le tableau
            tabRand[it] = irand; 
            it++;
        }
        itr = 0;
        estDedans = 0;
        irand = 0;

    }

    int tmp; // tri du tableau par ordre croissant pour faciliter le parcours du fichier 
    for(int i = 0; i < nc; ++i){
        for(int j = i + 1; j < nc; ++j){
            if(tabRand[i] > tabRand[j]){
                tmp = tabRand[i];
                tabRand[i] = tabRand[j];
                tabRand[j] = tmp;
            }
        }
    }
   
    it = 0;
    itr = 0;
    while(fgets(buffer, 100, fk)){
        if(it == tabRand[itr]){ // récuperation des lignes candidats et ecritures de celles ci dans le fichier candidat
            if (sscanf(buffer, " %s\n", str)==1){
                strcpy(tabCandidats[itr], str);
                fprintf(fc, "%s\n", tabCandidats[itr]); 
            }
            itr++;
        }
        it++;
    }

    fclose(fk);
    fclose(fc);

    // GENERE les declarations de vote (a partir de Keys) et les
    // enregistre dans un fichier Declaration.txt

    FILE *fkr = fopen("Keys.txt", "r");
    FILE *fs = fopen("Declarations.txt", "w");
    char str2[100];
    char str3[100];
    while(fgets(buffer, 256, fkr)){
        if (sscanf(buffer, " %s %s \n", str2, str3)==2){
            sKey = str_to_key(str3);
            long rand = rand_long(0, nc-1); //choix aléatoire de candidats et consitution de la déclaration
            Signature *si = sign(tabCandidats[rand], sKey);
            char *ss = signature_to_str(si);
            fprintf(fs, "%s %s %s \n", str2, 
            tabCandidats[rand], 
            ss);
            free(si->content);
            free(si);
            free(sKey);
            free(ss);
        }
    }
    fclose(fkr);
    fclose(fs);
    
    for(int i=0; i<nc;i++){
        free(tabCandidats[i]); // libération du tableau
    }
    free(tabCandidats);
    free(tabRand);  
}

void print_file_block(Block *block, char *name){
    // création du fichier comprenant les informations d'un bloc
    // parcours des valeurs du bloc et simple écriture dans le fichier name
    FILE *f = fopen(name, "w");
    assert(f);
    char *auth = key_to_str(block->author);
    fprintf(f, "%s\n", auth);
    free(auth);
    CellProtected *tmp = block->votes;
    while(tmp){
        char *pr = protected_to_str(tmp->data);
        fprintf(f, "%s\n", pr);
        free(pr);
        tmp = tmp->next;
    }
    fprintf(f, "%s\n", block->hash);
    fprintf(f, "%s\n", block->previous_hash);
    fprintf(f, "%d\n", block->nonce);
    fclose(f);
}

Block *read_file_block(char *nf){
    // constitution d'un bloc à partir de la lecture d'un fichier
    FILE *f = fopen(nf, "r");
    assert(f);
    Block *block = (Block *)malloc(sizeof(Block));
    char buffer[256];
    block->votes = create_cell_protected(NULL);
    CellProtected *droit = create_cell_protected(NULL);
    int nonce;

    if(fgets(buffer, 256, f)){ // premiere ligne = auteur
        block->author=str_to_key(buffer);
    }


    while(fgets(buffer, 256, f)){ // ensuite les déclarations
        char *tmp=malloc(sizeof(char)*256);
        char *tmp1=malloc(sizeof(char)*120);
        char *tmp2=malloc(sizeof(char)*50);
        char *tmp3=malloc(sizeof(char)*100);
        
        if(sscanf(buffer, " %s %s %s\n", tmp1, tmp2, tmp3) == 3){ // si il y'a bien 3 elements recuperés
            strcpy(tmp, tmp1);
            strcat(tmp, " ");
            strcat(tmp, tmp2);
            strcat(tmp, " ");
            strcat(tmp, tmp3);
            strcat(tmp, "\n");
            
            Protected *pr = str_to_protected(tmp); // création de la liste de votes du bloc
            block->votes = ajout_en_tete_CellPR(block->votes, pr);

        }
        else{
            free(tmp);
            block->hash=strdup(tmp1); // si la partie déclaration est passée on recuperation le hash qui arrive juste apres
            free(tmp2);
            free(tmp3);
            break;
        }

        free(tmp);
        free(tmp1);
        free(tmp2);
        free(tmp3);
    }

    // enfin previous hash et nonce

    if(fgets(buffer, 256, f)){
        buffer[strlen(buffer)-1]='\0';
        block->previous_hash=strdup(buffer); 
    }
    
    if(fgets(buffer, 256, f)){    
        if(sscanf(buffer, "%d", &nonce) == 1){
            block->nonce=nonce;
        }
    }

    fclose(f);

    while(block->votes){
        droit=ajout_en_tete_CellPR(droit, block->votes->data); //l'ajout en tete provoque certains probleme lors de 
        // l'ecriture->lecture->ecriture donc pour tjrs avoir la mm liste afin de faire des verification on la remet dans le bon ordre
        block->votes=block->votes->next;
    }
    delete_cell_protected(block->votes);
    block->votes=droit;
    return block;
}

void submit_vote(Protected* p){
    FILE *f=fopen("Pending_votes.txt","a");
    assert(f);
    char *str = protected_to_str(p); //ecriture de la declaration signée dans le fichier Pending_votes.txt
    fprintf(f,"%s\n", str);
    free(str);
    fclose(f);
}

void create_block(CellTree* tree, Key* author, int d){
    //lecture du fichier afin de recuperer la declaration signée
    CellProtected *pr = read_protected("Pending_votes.txt"); 
    // création du block
    Block *b = (Block *)malloc(sizeof(Block));
    b->author=author;
    b->votes=pr;
    b->nonce=0;

    // reconstitution de la chaine de hash
    CellTree *last = last_node(tree);
    
    if(!last || !last->block){
        b->previous_hash=strdup(" ");
        
    }else{
        b->previous_hash=strdup(last->block->hash);
    }
    
    char *block = block_to_str(b);
    b->hash=str_to_hash(block); //constitution de 'lidentifiant du bloc 
    free(block);

    compute_proof_of_work(b, d);
    
    add_child(tree, create_node(b));

    //sauvegarde du dernier block crée
    tree->block = b;

    // création du fichier Pending_block afin de stocker le block et supprimer le fichier des votes en attente 
    print_file_block(b, "Pending_block.txt");
    remove("Pending_votes.txt");

}

void add_block(int d, char* name){
    Block *b = read_file_block("Pending_block.txt"); //lecture du fichier afin de recuperer le block
    
    if (verify_block(b, d) == 1){ // verifie si le block est valide, si oui, cree un fichier "name"
        chdir("Blockchain/");
        print_file_block(b, name);
    }
    chdir("../");
    remove("Pending_block.txt"); // suppression du fichier Pending_block à chaque appel de la fonction
}

CellTree* read_tree(){
    int count=0;
    Block *b;
    CellTree *n;
    DIR *repc = opendir("./Blockchain/"); // ouverture du repertoire
    if(repc != NULL){
        struct dirent * dir ;
        while ((dir = readdir(repc))){ // parcours de repertoire afin d'avoir le nombre de block
            if (strcmp(dir->d_name, ".") !=0 && strcmp(dir->d_name, "..") !=0){
                count++;
            }
        }

        closedir(repc);
    }

    CellTree** T = (CellTree **)malloc(sizeof(CellTree *)*count);
    DIR *rep = opendir("./Blockchain/"); // reouverture du repertoire
    chdir("Blockchain/"); //permet de se localiser dans le repertoire afin de manipuler les fichier
    char *tmp;
    if(rep != NULL){
        struct dirent * dir ;
        int i = 0;
        while ((dir = readdir(rep))){ // parcours de repertoire afin de creer les nodes et les ajouter dans T
            if (strcmp(dir->d_name, ".") !=0 && strcmp(dir->d_name, "..") !=0){ //comparaison des noms de fichiers
                // création du block puis du noeud associé
                b=read_file_block(dir->d_name);
                n=create_node(b);
                if(i<count){
                    T[i] = n;
                }
                i++;
            }
        }

        closedir(rep);
    }

    // comparaison du hash et previous_hash afin de reconstituer les arbres
    for(int it=0; it<count; it++){
        for(int jt=0; jt<count; jt++){
            if(strcmp(T[it]->block->hash, T[jt]->block->previous_hash) == 0){
                add_child(T[it], T[jt]);
            }
        }
    }

    // parcours de T afin d'avoir le noeud racine
    for(int itr=0; itr<count; itr++){
        if(!T[itr]->father){
            return T[itr];
        }
    }
    
    return NULL;
}














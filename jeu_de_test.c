#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h> 
#include <assert.h>
#include <openssl/sha.h>
#include "chiffrement.h"
#include <dirent.h>
#include "struct.h"
#include "structure.h"
#include "readwrite.h"
#include "compute.h"

/*
PROJET : Blockchain appliquee a un processus electoral

ALALLAH Yassine - nÂ°etu : 28707696
CISSE Ousmane - nÂ°etu : 28711951

LU2IN006 

make
./jeu_de_test

------- POUR TESTER CHAQUE FONCTION : DECOMMENTER SA PARTIE -------

Chaque test est indÃ©pendant d'un autre. 

COMMENTER PLUSIEURS LIGNES : selectionner puis Ctrl+K+C
DECOMMENTER PLUSIEURS LIGNES : selectionner puis Ctrl+K+U

================ CORRECTIONS EVENTUELS A FAIRE : ================
-	Modpow ne doit pas faire de division par 0 donc verfier la valeur de n !
	Cela implique d'eviter de prendre des valeurs = 0 dans la construction de cle

-	Les Warnings dans les parties 2 et 3 sont dues au tableau de long que compose les signatures. 

-	signature_to_str pose peut etre pb mais a l'air d'aller bien dans la suite 

*/

#define BENCH(X, temps_initial, temps_final, temps_cpu)\
		temps_initial = clock();\
		X;\
		temps_final = clock();\
		temps_cpu=((double)(temps_final - temps_initial))/CLOCKS_PER_SEC\


int main(int argc, char** argv){
    srand(time(NULL));
	// printf("================================TEST DE LA PARTIE 1 ================================\n");

	// // is_prime_naive :
	// printf("=== Test de la fonction : is_prime_naive === \n");
	// printf("	- Pour le nombre 22 091, on attend 1 car il est premier. \n");
	// printf("	  Resultat de is_prime_naive(22 091) = %d \n", is_prime_naive(22091));
	// printf("	- Pour le nombre 22 092, on attend 0 car il n'est pas premier. \n"); 
	// printf("	  Resultat de is_prime_naive(22 092) = %d \n\n", is_prime_naive(22092));				 

	// // modpow_naive
	// printf("=== Test de la fonction : modpow_naive ===\n");
	// printf("	- La valeur attendue de (5^6 mod 23) est : 8 \n");
	// printf("	  Resultat de modpow_naive(5,6,23) = %ld \n\n", modpow_naive(5,6,23));

	// // modpow
	// printf("=== Test de la fonction : modpow ===\n");
	// printf("	- La valeur attendue de (5^6 mod 23) est : 8  \n");
	// printf("	  Resultat de modpow(5,6,23) = %d \n\n", modpow(5,6,23));

	// /* 
	// On suppose que les fonctions witness, rand_long et is_prime_miller ainsi que extended_gcd 
	// fonctionnent correctement car elles sont prÃ©dÃ©finies par le sujet 
	// */ 

	// // RANDOM_PRIME_NUMBER
	// printf("=== Test de la fonction : random_prime_number ===\n");
	// printf("	- Les valeurs generees doivent etre premieres et avoir une taille comprise entre 3 et 7.\n");
	// long p1 = random_prime_number(3,7,3000);
	// long q1 = random_prime_number(3,7,3000);
	// printf("	  Premiere valeur de random_prime_number(3,7,3000) = %ld \n", p1);
	// printf("	  PrimalitÃ© (avec is_prime_naive) : %d \n", is_prime_naive(p1));
	// printf("	  Seconde valeur de random_prime_number(3,7,3000) = %ld \n", q1);
	// printf("	  PrimalitÃ© (avec is_prime_naive) : %d \n\n", is_prime_naive(q1));

	// // GENERATE_KEYS_VALUES
	// printf("=== Test de la fonction : generate_keys_values ===\n");
	// printf("	- On genere 2 nombres premiers aleatoires pour la production de cles.\n");
	// long n,s,u;
	// long p2 = random_prime_number(3,7,3000);
	// long q2 = random_prime_number(3,7,3000);
	// generate_keys_values(p2,q2,&n,&s,&u);
	// printf("	  Cles generees : \n");
	// printf("	  	Cle publique : (%ld,%ld) \n", s,n);
	// printf("	  	Cle privee : (%ld,%ld) \n\n", n,u);

	// // ENCRYPT et DECRYPT
	// // les cles de cryptage pour les tests de ENCRYPT ET DECRYPT 
	// long n1,s1,u1;
	// long p3 = random_prime_number(3,7,3000);
	// long q3 = random_prime_number(3,7,3000);
	// generate_keys_values(p3,q3,&n1,&s1,&u1);
	// printf("=== Test des fonctions : encrypt et decrypt===\n");
	// printf("	- Cles generees : \n");
	// printf("	  	Cle publique : (%ld,%ld) \n", s1,n1);
	// printf("	  	Cle privee : (%ld,%ld) \n\n", n1,u1);
	// // encrypt
	// printf("	- On crypte, grace a la cle publique, la chaine de caracteres : 'cryptographie '. \n");
	// char c1[15] = { 'c', 'r', 'y', 'p', 't', 'o', 'g', 'r','a','p','h','i','e','\0' };
	// long* crypted1 = encrypt(c1,s1,n1);
	// printf("	  Chaine cryptee : %ld  \n\n", crypted1);
	// // decrypt
	// printf("	- On decrypte, grÃ¢ce a la cle privee generee, et on attend 'cryptographie' : %ld \n",crypted1);
	// char* decrypted1  = decrypt(crypted1,strlen(c1),u1,n1);
	// printf("	  Chaine decryptee : %s  \n\n", decrypted1);
	// free(decrypted1);
	// free(crypted1);


	// printf("================================ TEST DE LA PARTIE 2 ================================\n");
	// // INIT_KEYS 
	// printf("=== Test de la fonction : init_keys ===\n");
	// printf("	- On cree une cle dont les valeurs sont 22 et 23.  On affiche ses champs\n");
	// Key* cle1 = (Key*) malloc(sizeof(Key));
	// init_key(cle1,22,23);
	// printf("	- Affichage des champs de la cle : (%ld,%ld) \n",cle1->val,cle1->n);
	// free(cle1);

	// //  KEY_TO_STR
	// printf("\n=== Test de la fonction :  key_to_str ===\n");
	// printf("	- On cree une cle dont les valeurs sont 22 et 23, puis on la change en chaÃ®ne de caractÃ¨re.\n On l'affiche.\n");
	// Key* cle2 = (Key*) malloc(sizeof(Key));
	// init_key(cle2,22,23);
	// printf("	- Affichage de la cle sous forme de chaine : %s \n",key_to_str(cle2));
	// free(cle2);

	// // STR_TO_KEY
	// printf("\n=== Test de la fonction : key_to_str ===\n");
	// printf("	- On cree une chaine (22,23), puis on la change en cle.\n On affiche ses champs.\n");
	// Key* cle3 = str_to_key("(22,23)");;
	// printf("	- Affichage des champs de la cle : (%ld,%ld) \n",cle3->val,cle3->n);
	// free(cle3);

	// // INIT_PAIR_KEYS
	// printf("\n=== Test de la fonction : init_pair_keys ===\n");
	// printf("	- Les valeurs dans la cle doivent avoir une taille comprise entre 3 et 7.\n");
	// Key* clepub1 = (Key*) malloc(sizeof(Key));
	// Key* clepv1 = (Key*) malloc(sizeof(Key));
	// init_pair_keys(clepub1,clepv1,3,7);
	// printf("	  	Cle publique : (%ld,%ld) \n", clepub1->val,clepub1->n);
	// printf("	  	Cle privee : (%ld,%ld) \n\n", clepv1->val,clepv1->n);
	// free(clepub1);
	// free(clepv1);

	// // ============================================= 
	// // INIT_SIGNATURE 
	// printf("=============================================\n");
	// printf("=== Test de la fonction : init_signature ===\n");
	// printf("	- On cree une signature dont le contenu est : 1234.  On affiche ses champs\n");
	// Signature* sign1 = init_signature(1234,4);
	// printf("	- Affichage des champs de la signature : \n	 ->%ld\n 	->%d \n\n",sign1->content,sign1->size);
	// free(sign1);

	// // SIGN 
	// printf("=== Test de la fonction : sign ===\n");
	// printf("	- On cree la signature a partir de la cle <cle4> d'un citoyen et du message du candidat vote : Trump.\n");
	// Key* cle4 = (Key*) malloc(sizeof(Key));
	// init_key(cle4,04,01);
	// char trump[15] = { 't', 'r', 'u', 'm', 'p','\0' };
	// Signature* sign2 = sign(trump,cle4);
	// printf("	- Affichage des champs de la signature : \n	 ->%ld\n 	->%d \n\n",sign2->content,sign2->size);
	// free(sign2->content);
	// free(cle4);
	// free(sign2);

	// // SIGNATURE_TO_STR
	// printf("=== Test de la fonction :  signature_to_str ===\n");
	// printf("	- On cree la signature a partir de la cle <cle4> d'un citoyen et du message du candidat vote : Trump.\n");
	// printf("	  On la change en chaÃ®ne de caractÃ¨re. On l'affiche.\n");
	// Key* cle5 = (Key*) malloc(sizeof(Key));
	// init_key(cle5,05,01);
	// char obama[15] = { 'o', 'b', 'a', 'm', 'a','\0' };
	// Signature* sign3 = sign(obama,cle5);
	// char *s = signature_to_str(sign3);
	// printf("	- Affichage de la signature sous forme de chaine : %s \n\n",s);
	// free(cle5);
	// free(sign3->content);
	// free(sign3);
	// free(s);

	// // STR_TO_SIGNATURE
	// printf("=== Test de la fonction : str_to_signature ===\n");
	// printf("	- On cree une chaine puis on la change en signature. On affiche ses champs.");
	// char sig_str[] = "#0#0#0#0#0#";
	// Signature* sign4 = str_to_signature(sig_str);
	// printf("	- Affichage des champs de la signature : \n	 content : %ld 	size : %d \n\n",sign4->content,sign4->size);
	// free(sign4->content);
	// free(sign4);

	// STRUCTURE PROTECTED
	printf("=== Test des fonctions de la structure protected ===\n");
	printf("	- On cree une declaration signee a partir de 2 cles. \n");
	// creation de la declaration :
	Key *clepub6 = malloc(sizeof(Key));
    Key *cleS7 = malloc(sizeof(Key));
    init_pair_keys(clepub6, cleS7, 3 ,7);
	char* mess1 = key_to_str(clepub6);
	Signature* sign5 = sign(mess1,cleS7);
	Protected* pro1 = init_protected(clepub6,mess1,sign5);

	printf("	- Affichage des champs de la declaration (init_protected): \n	 cle : %s  mess : %s	signature : %s\n",key_to_str(pro1->pKey), pro1->mess, signature_to_str(pro1->sgn));
	printf("	- Affichage de la signature sous forme de chaine (protected_to_str) : %s \n\n",protected_to_str(pro1));
	Protected* pro2 = str_to_protected(protected_to_str(pro1));
	printf("	- Affichage des champs de la declaration apres conversion de la chaine (str_to_protected): \n	 cle : %s  mess : %s	signature : %s\n",key_to_str(pro2->pKey), pro2->mess, signature_to_str(pro2->sgn));
	printf("	- Verification de la validite de la declaration (verify) - Valeur attendue = 1\n");
	printf("	  Valeur obtenue : %d\n",verify(pro1));
	free(pro2);
	free(sign5);
	free(pro1);
	free(mess1);


	// // =============================================
	// // GENERATE_RANDOM_DATA
	// printf("=============================================\n");
	// printf("=== Test de la fonction generate_random_data ===\n");
	// printf("	- On genere 3 fichiers contenant 20 votants, 6 candidats et les declarations de vote (valeurs aleatoires) \n");
	// generate_random_data(20,6);
	// printf("	- Fichiers termines\n");


	/*
	// ============================================= 
	// LISTE CHAINEE DE CLE : CELLKEYS 
	printf("\n=============================================\n");
	printf("================================ TEST DE LA PARTIE 3 ================================\n");
	// creation
	printf("=== Tests des listes chainee de cles (cellKey)  ===\n");
	printf("	- On cree une cellule de liste chainee de cle contenant la cle (06,01) : create_cell_key\n");
	Key* cle6 = (Key*) malloc(sizeof(Key));
	init_key(cle6,06,01);
	CellKey* cellkey1 = create_cell_key(cle6);
	// affichage
	printf("	- On affiche la liste contenant l'unique cellule de cle  (06,01) : print_list_keys \n");
	print_list_keys(cellkey1);
	printf("\n");
	//ajout 
	printf("	- On ajoute a la liste la cle (06,01) dans une nouvelle liste puis on l'affiche: ajout_en_tete_CellKey\n");
	Key* cle7 = (Key*) malloc(sizeof(Key));
	init_key(cle7,07,01);
	CellKey* cellkey2 = ajout_en_tete_CellKey(cellkey1,cle7);
	print_list_keys(cellkey2);
	printf("\n");
	// lecture depuis le fichier text.txt :
	printf("	- On cree une nouvelle liste dans laquelle on ecrit toutes les cles du fichier text.txt : read_public_keys\n");
	CellKey* cellkey3 = read_public_keys("keys.txt");
	print_list_keys(cellkey3);
	printf("\n");

	// suppression des listes creees 
	printf("	- On supprime les 3 listes qu'on vient de creer: delete_list_keys\n");
	delete_list_keys(cellkey2);
	delete_list_keys(cellkey3);
	printf("	  ...\n");
	printf("	  Suppression terminee\n");
	*/


	/*
	// LISTE CHAINEE DE DECLARATIONS : CELLPROTECTED
	printf("=============================================\n");
	// creation
	printf("=== Tests des listes chainee de declarations (cellprotected)  ===\n");
	printf("	- On cree une cellule de liste chainee de declaration contenant une declaration de vote : create_cell_protected\n");
	// creation d'une declaration 
	Key *clepub7 = malloc(sizeof(Key));
    Key *cleS8 = malloc(sizeof(Key));
    init_pair_keys(clepub7, cleS8, 3 ,7);
	char* mess2 = key_to_str(clepub7);
	Signature* sign6 = sign(mess2,cleS8);
	Protected* pro3 = init_protected(clepub7,mess2,sign6);
	// creation d'une cellule de declaration 
	CellProtected* cellpro1 = create_cell_protected(pro3);
	// affichage
	printf("	- On affiche la liste contenant l'unique declaration : afficher_cellPR \n");
	afficher_cellPR(cellpro1);
	printf("\n");
	//ajout d'une declaration
	printf("	- On ajoute a la liste la declaration dans une nouvelle liste puis on l'affiche: ajout_en_tete_CellPR\n");
	Key *clepub8 = malloc(sizeof(Key));
    Key *cleS9 = malloc(sizeof(Key));
    init_pair_keys(clepub8, cleS9, 3 ,7);
	char* mess3 = key_to_str(clepub8);
	Signature* sign7 = sign(mess3,cleS9);
	Protected* pro4 = init_protected(clepub8,mess3,sign7);

	CellProtected* cellpro2 = ajout_en_tete_CellPR(cellpro1,pro4);
	afficher_cellPR(cellpro2);
	printf("\n");

	// lecture depuis le fichier Declarations.txt :
	printf("	- On cree une nouvelle liste dans laquelle on ecrit toutes les declarations du fichier declarations.txt : read_protected\n");
	CellProtected* cellpro3 = read_protected("Declarations.txt");
	afficher_cellPR(cellpro3);
	printf("\n");

	// suppression des declarations fausses
	printf("	- On supprime les declarations fausses de la precedente liste.\n");
	delete_fraud_list_protected(&cellpro3);
	afficher_cellPR(cellpro3);
	printf("\n");
	printf("	  Suppression terminee\n");

	// suppression des listes creees 
	printf("	- On supprime les 3 listes qu'on vient de creer : delete_list_protected\n");
	delete_list_protected(cellpro2);
	delete_list_protected(cellpro3);
	printf("	  ...\n");
	printf("	  Suppression terminee\n");

	*/
	
    return 0;


}
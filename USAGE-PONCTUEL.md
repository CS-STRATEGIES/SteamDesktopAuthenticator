# SDA pour une utilisation ponctuelle

Cette copie de Steam Desktop Authenticator est preparee pour Windows 10/11 64 bits.
Le dossier publie embarque .NET 10.0.12 : aucune installation de .NET, de Python,
de Node.js ou de Visual Studio n'est necessaire pour l'utiliser.

## Lancement

Le dossier prepare pour le transfert est `artifacts/SDA-transfer-win-x64`.
Depuis la racine du depot, lancer directement :

```powershell
& '.\artifacts\SDA-transfer-win-x64\Steam Desktop Authenticator.exe'
```

Conserver les DLL et les autres fichiers a cote de l'executable. L'application
cree son dossier `maFiles` a cet emplacement. Activer le chiffrement propose et
conserver le mot de passe et le code de recuperation dans un gestionnaire de secrets.
Ne pas envoyer le dossier utilise dans GitHub, une issue ou une conversation.

## Transferer Steam Guard depuis le telephone (parcours conseille ici)

**Ne pas supprimer l'authentificateur du telephone. Ne pas utiliser Setup New Account.**
Le transfert remplace les secrets du telephone par de nouveaux secrets dans SDA.
Il demande une connexion autorisee au compte puis une validation SMS. Ce n'est pas
une extraction des anciens secrets iOS et aucune operation reelle n'est executee
par les tests de ce depot.

Steam annonce une restriction de **2 jours** pour un transfert. La suppression
prealable de l'authentificateur impose, elle, **15 jours**. Le serveur Steam reste
responsable de la restriction effective : cette version ne promet pas une date de
deblocage et ne contourne aucune restriction existante.

1. Garder Steam Guard actif sur l'iPhone et verifier l'acces au numero de telephone
   associe au compte. Conserver le code de recuperation actuel.
2. Lancer SDA. Sur l'ecran d'accueil, choisir le bouton de premiere utilisation
   pour afficher la fenetre principale.
3. Ouvrir **File > Transfer Authenticator**, puis **Sign in and transfer**.
4. Saisir l'identifiant de connexion et le mot de passe Steam, puis le code
   Steam Guard actuellement affiche par l'application sur le telephone.
5. Choisir et conserver le mot de passe de chiffrement. Si SDA a deja des comptes,
   ils doivent etre chiffres ; le parcours demande alors leur mot de passe actuel.
6. Steam envoie un SMS. Saisir son code uniquement dans SDA. La validation de cette
   etape remplace l'authentificateur du telephone. Annuler avant validation ne
   soumet pas le transfert.
7. Attendre le message indiquant que l'authentificateur est enregistre, puis
   conserver son **nouveau code de recuperation** et sauvegarder tout `maFiles`.
8. Verifier une connexion Steam avec le code genere par SDA et lire la restriction
   affichee par Steam. Laisser **Auto-confirm trades** et
   **Auto-confirm market transactions** desactives.

Le transfert utilise `ITwoFactorService/RemoveAuthenticatorViaChallengeStart`, puis
`RemoveAuthenticatorViaChallengeContinue` avec `generate_new_token=true` et
`version=2`. Malgre le nom de ces methodes, ce parcours demande un remplacement ;
il n'appelle jamais `RemoveAuthenticator`, `AddAuthenticator` ou leur finalisation.

### Sauvegarde et interruption

Avant le SMS, SDA cree et relit une sauvegarde autonome `transfer-*.sda-transfer`
dans `maFiles`. Elle est chiffree par AES-256-GCM avec une cle derivee du mot de
passe par PBKDF2-SHA256 (600 000 iterations). La reponse de Steam y est enregistree
avant interpretation et avant ecriture du maFile. Le format des maFiles conserve
le chiffrement historique de SDA pour compatibilite.

- Si l'ecriture de la reponse echoue, garder la fenetre ouverte et choisir un
  autre emplacement. Le programme conserve la reponse en memoire sans la renvoyer.
- Si la reponse a ete sauvegardee mais que le maFile ou le manifest n'a pas pu etre
  enregistre, rouvrir **File > Transfer Authenticator > Recover saved transfer**.
  Choisir la sauvegarde et son mot de passe. Cette recuperation fonctionne hors
  ligne et n'effectue aucun nouveau transfert.
- Apres une coupure reseau, Steam peut avoir termine l'operation sans que SDA ait
  recu les nouveaux secrets. Une sauvegarde sans reponse ne peut pas les recreer.
  Verifier le compte avec Steam ou son assistance avant toute nouvelle tentative.
  Aucun renvoi automatique ni suppression de secours n'est effectue.
- Un refus SMS explicite permet de corriger la saisie. Ne pas multiplier les
  demandes SMS : Steam peut les limiter.

### Utiliser les secrets dans EzSteam

Les champs `account_name`, `shared_secret` et `identity_secret` du maFile
correspondent a `MAIN_STEAM_ACCOUNT_NAME`, `MAIN_STEAM_SHARED_SECRET` et
`MAIN_STEAM_IDENTITY_SECRET`. Ajouter separement `MAIN_STEAM_PASSWORD` dans la
configuration privee du serveur EzSteam. Ne jamais commiter ni envoyer ces valeurs.
EzSteam ne demande pas le code de recuperation.

Pour lire le maFile dans un editeur local avec l'interface historique :
**Manage Encryption**, saisir le mot de passe actuel, puis laisser les deux nouveaux
champs vides. Cela dechiffre tous les comptes locaux. Copier les valeurs necessaires
dans le gestionnaire de secrets, fermer le fichier, puis reactiver
**Setup Encryption**. La sauvegarde `.sda-transfer` reste chiffree avec son mot de
passe d'origine. Garder ce mot de passe meme si celui des maFiles change.

Avant d'activer le compte principal dans EzSteam, verifier son reglage
`cancelTime` : le code examine le 08/10/2026 fixe 900000 ms, soit une annulation
automatique des offres envoyees apres 15 minutes. `null` desactive ce comportement.
Cette modification concerne EzSteam et n'est pas effectuee par ce fork SDA.

Apres redeploiement d'EzSteam, utiliser son `/docs` et le jeton Bearer pour verifier
`GET /api/trades/status` (bon SteamID, `isLoggedIn` et secrets presents),
`GET /api/trades/2fa-code` (meme code que SDA au meme instant), puis
`GET /api/trades/confirmations` (lecture sans acceptation). Les connexions du
systeme cookies/inventaires restent distinctes de la configuration de trading.

SDA peut ensuite rester ferme. Conserver l'authentificateur actif et ses sauvegardes.
Un nouveau transfert vers l'application officielle du telephone remplacera a
nouveau les secrets : ne pas supposer que ceux d'EzSteam resteront valides.

### References du transfert

- [Regles de transfert Steam](https://help.steampowered.com/en/faqs/view/7EFD-3CAE-64D3-1C31).
- [Restriction apres suppression](https://help.steampowered.com/en/faqs/view/348C-AB68-0C94-5442).
- [Schema du protocole TwoFactor](https://github.com/SteamDatabase/Protobufs/blob/master/steam/steammessages_twofactor.steamclient.proto).
- [Parcours existant dans steamguard-cli](https://github.com/dyc3/steamguard-cli/blob/master/steamguard/src/accountlinker.rs).
  Implementation C# independante utilisant les messages deja fournis par SteamKit2.

## Perimetre de cette version

- SteamKit2 3.4.0 et SteamAuth au commit `a14ffc22b5a37f77582696afab1c5a60e406709a`.
- Newtonsoft.Json 13.0.4, protobuf-net 3.4.30, System.IO.Hashing 10.0.12,
  ZstdSharp.Port 0.8.8 et CommandLineParser 2.9.1.
- Versions transitives et empreintes NuGet conservees dans `dependencies/`.
- Audit NuGet des dependances directes et transitives lors de la construction.
- Controles hors ligne avec des donnees fictives : codes Steam Guard, import,
  compatibilite du chiffrement, construction des formulaires, protocole de transfert,
  refus SMS, perte reseau, reponses incompletes, sauvegarde et recuperation.

La verification ne constitue pas un audit complet du code. Le format de chiffrement
historique de SDA est conserve et l'authentification reelle n'est pas testee par les
controles hors ligne. L'avertissement original au lancement reste present.
Les confirmations automatiques restent desactivees par defaut.

## Reconstruction (developpement uniquement)

Avec le SDK .NET 10.0.401 et Git :

```powershell
git clone --recurse-submodules https://github.com/CS-STRATEGIES/SteamDesktopAuthenticator.git
cd SteamDesktopAuthenticator
.\build-portable.ps1 -OutputDirectory 'artifacts\SDA-transfer-win-x64'
```

Le script refuse un dossier de sortie existant afin de ne pas ecraser ou inclure
des secrets. Il restaure les versions verrouillees, execute les controles, consulte
les avis NuGet et publie le dossier autonome. Aucun installateur ni ZIP n'est produit.
Le runtime est fixe a 10.0.12 pour cette utilisation imminente. Pour une utilisation
ulterieure, les correctifs disponibles devront etre verifies de nouveau.

Pour construire a cote d'une version deja utilisee, fournir un nouveau dossier :

```powershell
.\build-portable.ps1 -OutputDirectory 'artifacts\SDA-transfer-win-x64'
```

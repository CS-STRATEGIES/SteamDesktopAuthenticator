# SDA pour une utilisation ponctuelle

Cette copie de Steam Desktop Authenticator est preparee pour Windows 10/11 64 bits.
Le dossier publie embarque .NET 10.0.12 : aucune installation de .NET, de Python,
de Node.js ou de Visual Studio n'est necessaire pour l'utiliser.

## Lancement

Depuis la racine du depot, lancer directement :

```powershell
& '.\artifacts\SDA-win-x64\Steam Desktop Authenticator.exe'
```

Conserver les DLL et les autres fichiers a cote de l'executable. L'application
cree son dossier `maFiles` a cet emplacement. Activer le chiffrement propose et
conserver le mot de passe et le code de recuperation dans un gestionnaire de secrets.
Ne pas envoyer le dossier utilise dans GitHub, une issue ou une conversation.

SDA configure un authentificateur ou importe un fichier existant. Une connexion
au compte ne recupere pas les secrets d'un authentificateur deja sur un telephone.
Si Steam Guard est deja actif, ne pas le supprimer pour essayer le logiciel.
La procedure adaptee doit etre determinee avant toute modification de Steam Guard.

## Perimetre de cette version

- SteamKit2 3.4.0 et SteamAuth au commit `a14ffc22b5a37f77582696afab1c5a60e406709a`.
- Newtonsoft.Json 13.0.4, protobuf-net 3.4.30, System.IO.Hashing 10.0.12,
  ZstdSharp.Port 0.8.8 et CommandLineParser 2.9.1.
- Versions transitives et empreintes NuGet conservees dans `dependencies/`.
- Audit NuGet des dependances directes et transitives lors de la construction.
- Controles hors ligne avec des donnees fictives : codes Steam Guard, import,
  compatibilite du chiffrement, construction des formulaires et initialisation SteamKit.

La verification ne constitue pas un audit complet du code. Le format de chiffrement
historique de SDA est conserve et l'authentification reelle n'est pas testee par les
controles hors ligne. L'avertissement original au lancement reste present.
Les confirmations automatiques restent desactivees par defaut.

## Reconstruction (developpement uniquement)

Avec le SDK .NET 10.0.401 et Git :

```powershell
git clone --recurse-submodules https://github.com/CS-STRATEGIES/SteamDesktopAuthenticator.git
cd SteamDesktopAuthenticator
.\build-portable.ps1
```

Le script refuse un dossier de sortie existant afin de ne pas ecraser ou inclure
des secrets. Il restaure les versions verrouillees, execute les controles, consulte
les avis NuGet et publie le dossier autonome. Aucun installateur ni ZIP n'est produit.
Le runtime est fixe a 10.0.12 pour cette utilisation imminente. Pour une utilisation
ulterieure, les correctifs disponibles devront etre verifies de nouveau.

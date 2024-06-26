## 누가 더 빠른가?
   
### 일반적인 문자열 검색 함수
google.com : 0.000039 seconds  
naver.com : 0.000022 seconds  
hloljob.com : 0.001063 seconds   
uskawjdu.iptime.org (차단이 안된 사이트 ) : 0.005253 seconds   
    
### sqlite 사용, B+ Tree 인덱싱 검색 알고리즘
google.com : 0.000163 seconds   
naver.com : 0.000149 seconds   
hloljob.com : 0.000154 seconds   
uskawjdu.iptime.org (차단이 안된 사이트 ) : 0.000184 seconds   
  
## 결론  
일반적인 문자열 함수를 사용할 경우  
반복문을 통해서 같은 모든 문자열 리스트를 검사합니다.  
이때, google.com 와 같이 리스트의 앞에 있는 경우에는 검색 알고리즘이 굉장히 빠르게 찾아낼 수 있습니다.   
하지만, hloljob.com 와 같이 리스트에 마지막에 위차한 경우 느린 성능을 보입니다. (가장 마지막에 검삭하므로)  
 
sqlite를 B+ Tree 알고리즘을 사용해서 인덱싱 검색을 진행합니다.  
어떤 문자열이든 검색시간은 비슷하며 속도가 빠릅니다. 
비록 위에 실험에서는 sqlite 를 사용한 방법이 다소 속도 느리다고 해석될 수 있으나  
리스트의 길이가 100배 1000배 더 많이진다면 이 방법이 더욱 빠를 것 입니다.  
  
sqlite를 사용하지 않고 B+ Tree 인덱싱 검색 알고리즘은 C언어로 구현한다면,  
검색 속도는 어마무시하게 빨라질 것 입니다.  
  
나름 재미있는 실험이었으며, 아쉬운 점은 시간이 부족하여 B+ Tree는 구현하지 않았고  
ChatGpt의 도움을 받은 코드가 몇몇 있다는 것 입니다.  
  
한달동안 수업을 맡아주신 멘토님에게 감사를 전합니다.  


![capture](/image1.png)
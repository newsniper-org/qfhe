# Q-FHE: 프레파라타 부호 및 쿼터니언 대수 기반 FHE 스킴의 수학적 정의

## I. 시스템 파라미터 및 대수 구조

본 장에서는 Q-FHE 스킴을 구성하는 기본 파라미터와 대수적 구조를 정의한다.

### 1.1. 기본 대수 구조

*   **쿼터니언 대수 (Quaternion Algebra):** $B = (-1, -1)_{\mathbb{Q}}$ (해밀턴 쿼터니언 대수).
*   **극대 위수 (Maximal Order):** $B$ 내의 특정 극대 위수 $\mathcal{O}$ (예: 후르비츠 정수).
*   **다항식 환 (Polynomial Ring):** $n$을 2의 거듭제곱으로 할 때, 평문 및 암호문 연산은 다항식 환 $\mathcal{R} = \mathcal{O}[x]/(x^n+1)$ 위에서 정의된다.
*   **모듈 랭크 (Module Rank):** $d \in \mathbb{Z}^+$.
*   **평문 공간 (Plaintext Space):** $\mathcal{R}_t = (\mathcal{O}/t\mathcal{O})[x]/(x^n+1)$, 여기서 $t$는 평문 모듈러스.
*   **암호문 공간 (Ciphertext Space):** $\mathcal{R}_{q_i} = (\mathcal{O}/q_i\mathcal{O})[x]/(x^n+1)$, 여기서 $q_i$는 모듈러스 체인의 $i$번째 암호문 모듈러스.
*   **모듈러스 체인 (Modulus Chain):** $L$ 레벨의 곱셈 깊이를 지원하기 위한 소수들의 수열 $q_L > q_{L-1} > \dots > q_0$.
*   **스케일링 인자 (Scaling Factor):** $\Delta_i = \lfloor q_i/t \rfloor$.

### 1.2. 오류 정정 부호 (ECC)

*   **프레파라타 부호 (Preparata Code):** 홀수 $m_{\text{code}} \ge 3$에 대해, 파라미터 $(N=2^{m_{\text{code}}+1}-1, k=N-2m_{\text{code}}-2, d_{\min}=5)$를 갖는 비선형 이진 부호 $\mathcal{P}_{m_{\text{code}}}$. 이 부호는 $\mathbb{Z}_4$-선형 구조를 가진다.[1, 2]
*   **인코딩/디코딩 함수:**
    *   `ECC.Encode`: 평문 메시지 $m$을 프레파라타 부호어 $\mathbf{c} \in \mathcal{P}_{m_{\text{code}}}$로 변환.
    *   `ECC.Decode`: 잡음 섞인 부호어 $\mathbf{c}'$를 원본 메시지 $m$으로 복원.
*   **오류 분포 ($\chi_{\text{Prep}}$):** 프레파라타 부호 $\mathcal{P}_{m_{\text{code}}}$의 부호어 집합에서 균등 랜덤하게 원소를 샘플링하여 $\mathcal{R}_{q_i}$의 원소로 임베딩하는 분포.

### 1.3. 보안 수준별 파라미터

보안 파라미터 $\lambda$에 따라 Q-MLWE 문제의 어려움을 보장하기 위한 파라미터 집합을 정의한다. 이는 알려진 격자 공격(예: BKZ)에 대한 분석에 기반한다.[3, 4, 5, 6, 7]

| 보안 수준 ($\lambda$) | 모듈 랭크 ($d$) | 다항식 차수 ($n$) | 최대 모듈러스 ($\log_2 q_L$) | 오류 분포 ($\mathcal{P}_{m_{\text{code}}}$) |
| :--- | :---: | :---: | :---: | :---: |
| 128-bit | 2 | 2048 | $\approx 600$ | $\mathcal{P}(9)$ |
| 160-bit | 3 | 2048 | $\approx 750$ | $\mathcal{P}(11)$ |
| 192-bit | 3 | 4096 | $\approx 900$ | $\mathcal{P}(11)$ |
| 224-bit | 4 | 4096 | $\approx 1050$ | $\mathcal{P}(13)$ |
| 256-bit | 4 | 4096 | $\approx 1200$ | $\mathcal{P}(13)$ |

---

## II. 핵심 암호화 알고리즘

### 2.1. 키 생성 (`KeyGen(1^\lambda)`)

*   **비밀키 (sk):**
    *   작은 정수 계수를 갖는 다항식들의 분포 $\chi_{\text{key}}$에서 $\mathbf{s}' \leftarrow \chi_{\text{key}}^d$를 샘플링.
    *   $\mathbf{sk} \leftarrow (1, \mathbf{s}') \in \mathcal{R}_{q_L}^{d+1}$.

*   **공개키 (pk):**
    *   $\mathbf{A}' \leftarrow U(\mathcal{R}_{q_L}^{m \times d})$를 균등 랜덤하게 샘플링.
    *   $\mathbf{e} \leftarrow \chi_{\text{Prep}}^m$를 샘플링.
    *   $\mathbf{b} \leftarrow \mathbf{A}'\mathbf{s}' + \mathbf{e} \in \mathcal{R}_{q_L}^m$.
    *   $\mathbf{pk} \leftarrow (\mathbf{b}, -\mathbf{A}') \in \mathcal{R}_{q_L}^{m \times (d+1)}$.

*   **재선형화 키 (rlk):**
    *   비밀키 $\mathbf{s}'$의 텐서곱 $\mathbf{s}' \otimes \mathbf{s}'$의 각 성분 $s_i s_j$를 새로운 공개키로 암호화하여 생성. 4원수의 비가환성을 고려하여 $s_i s_j$와 $s_j s_i$를 모두 포함해야 한다.[8, 9, 10, 11, 12, 13]

### 2.2. 암호화 (`Encrypt(pk, m)`)

1.  평문 메시지 $m \in \mathcal{R}_t$를 부호어 $\mathbf{c} \leftarrow \text{ECC.Encode}(m)$로 변환.
2.  작은 계수를 갖는 랜덤 벡터 $\mathbf{r} \in \mathcal{R}_{q_L}^m$를 샘플링.
3.  암호문 $\mathbf{ct} \in \mathcal{R}_{q_L}^{d+1}$를 계산:
    $$ \mathbf{ct} \leftarrow (\mathbf{r}^T \mathbf{b} + \Delta_L \cdot \mathbf{c}, -\mathbf{r}^T \mathbf{A}') $$

### 2.3. 복호화 (`Decrypt(sk, ct)`)

1.  암호문 $\mathbf{ct} = (c_0, \mathbf{c}_1) \in \mathcal{R}_{q_i} \times \mathcal{R}_{q_i}^d$와 비밀키 $\mathbf{sk} = (1, \mathbf{s}')$의 내적을 계산:
    $$m' \leftarrow c_0 + \langle \mathbf{c}_1, \mathbf{s}' \rangle \pmod{q_i}$$
2.  스케일링을 되돌려 잡음 섞인 부호어 $\mathbf{c}'$를 복원:
    $$\mathbf{c}' \leftarrow \left\lfloor \frac{t}{q_i} \cdot m' \right\rceil \pmod t$$
3.  ECC 디코더를 사용하여 최종 메시지 $m$을 복원:
    $$m \leftarrow \text{ECC.Decode}(\mathbf{c}')$$

---

## III. Q-FHE를 위한 프로그래머블 부트스트래핑

### 3.1. 모듈러스 스위칭 (Modulus Switch)

*   입력 암호문 $\mathbf{ct}$의 모듈러스를 큰 값 q에서 부트스트래핑을 위한 작은 값 $p_{\text{boot}}$로 낮춥니다. 이 과정을 통해 메시지 대비 잡음의 영향을 거의 무시할 수 있을 정도로 만든다.

### 3.2. 블라인드 회전 (Blind Rotate)

*   평가할 함수 f의 룩업 테이블(LUT)을 인코딩한 평문 테스트 벡터 $\text{TestVector}(f)$를 준비합니다.
*   입력 암호문 $\mathbf{ct}$로부터 메시지 m을 지수로 갖는 암호화된 단항식 $\text{Monomial}(\mathbf{ct})$를 생성한다.
*   이 둘 사이의 동형 외적(external product)을 계산하여 회전된 암호문 $\mathbf{ct}_{\text{rot}}$를 얻는다.
$$\mathbf{ct}_{\text{rot}} = \text{TestVector}(f) \times \text{Monomial}(\mathbf{ct})$$
*   이 연산은 쿼터니언의 행렬 표현을 통해 일련의 암호화된 행렬-벡터 곱셈으로 수행된다. 연산 결과로, $\mathbf{ct}_{\text{rot}}$의 상수항(constant term)에는 $f(m)$이 암호화된 값이 위치하게 된다.

### 3.3. 샘플 추출 (Sample Extract)

*   회전된 암호문 $\mathbf{ct}_{\text{rot}}$에서 $f(m)$을 암호화하고 있는 상수항 부분만을 추출하여 새로운 암호문을 생성한다.

### 3.4. 키 스위칭 (Key Switch)

*   추출된 암호문은 부트스트래핑 키로 암호화되어 있는데, 이를 원래의 비밀키 $\mathbf{sk}$로 다시 암호화된 형태로 변환하는 키 스위칭 과정을 수행한다.

---

## IV. 동형 연산

### 4.1. 기본 사칙연산

*   **덧셈/뺄셈:**
    $$ \mathbf{ct}_{\text{add/sub}} \leftarrow \mathbf{ct}_1 \pm \mathbf{ct}_2 = (c_{1,0} \pm c_{2,0}, \mathbf{c}_{1,1} \pm \mathbf{c}_{2,1}) $$

*   **곱셈:**
    1.  두 암호문 $\mathbf{ct}_1, \mathbf{ct}_2$의 텐서곱을 계산하여 2차 암호문 $\mathbf{ct}_{\text{quad}}$를 생성. 이는 비밀키 $\mathbf{sk} \otimes \mathbf{sk}$에 대한 암호문이다.[14, 15, 16, 17, 18, 19, 20]
    2.  재선형화 키 $\mathbf{rlk}$를 사용하여 $\mathbf{ct}_{\text{quad}}$를 1차 암호문 $\mathbf{ct}_{\text{mult}}$로 변환:
        $$\mathbf{ct}_{\text{mult}} \leftarrow \text{Relinearize}(\mathbf{rlk}, \mathbf{ct}_{\text{quad}})$$
    3.  모듈러스 스위칭을 통해 잡음 관리: $\mathbf{ct}_{\text{mult}}$를 $q_i$에서 $q_{i-1}$로 스케일링.[21, 22, 23]

*   **나눗셈:** $1/x$의 근사를 위해 뉴턴-랩슨 반복법 $y_{k+1} = y_k(2 - x y_k)$을 사용. 각 곱셈 단계 후 재선형화 및 잡음 관리가 필요.

### 4.2. 비트 단위 연산

비트 단위 연산은 프로그래머블 부트스트래핑(PBS)을 통해 구현된다. 평문이 $\{0, 1\}$로 인코딩되었다고 가정한다.

*   **기본 게이트 (NAND):**
    $$\text{NAND}(a, b) = 1 - ab$$
    암호화된 비트 $\text{Enc}(a), \text{Enc}(b)$에 대해, 동형 곱셈과 덧셈을 사용하여 $\text{Enc}(1 - ab)$를 계산한다. 각 게이트 연산 후 PBS를 통해 잡음을 초기화한다.

*   **기타 비트 연산:**
    *   $\text{NOT}(a) = 1 - a$
    *   $\text{AND}(a, b) = ab$
    *   $\text{OR}(a, b) = a+b - ab$
    *   $\text{XOR}(a, b) = a+b - 2ab$

*   **비트 시프트/회전:**
    *   **Shift Left (`<< k`):** 평문 다항식 $m(x)$에 $x^k$를 곱하는 것과 동일. 이는 암호문에 대한 특정 자동형성(automorphism) 변환으로 구현된다.
    *   **Rotate Left (`rot k`):** 평문 다항식 $m(x)$에 $x^k$를 곱하고 $x^n+1$로 나눈 나머지를 취하는 것과 동일. 이는 암호문에 대한 특정 갈루아(Galois) 변환으로 구현된다.

### 4.3. 고급 함수 (프로그래머블 부트스트래핑 기반)

임의의 함수 $f(x)$는 PBS를 통해 평가된다.

1.  **함수 $f$를 룩업 테이블(LUT)로 인코딩.**
2.  암호문 $\text{Enc}(x)$에 대해 PBS를 수행하여 $\text{Enc}(f(x))$를 계산.

*   **초월함수 (지수/로그, 삼각/역삼각, 쌍곡선/역쌍곡선):**
    *   함수를 특정 정의역 내에서 체비쇼프 다항식(Chebyshev Polynomials)으로 근사한다.[24, 25, 26]
    *   또는, 함수 값을 이산화하여 LUT로 만들고 PBS를 통해 평가한다.

*   **비교 및 반올림 연산:**
    *   **대소 비교 (`>`):** $\text{Compare}(a, b) > 0 \iff a > b$. 이는 $\text{PBS}(\text{Enc}(a-b), \text{LUT}_{\text{sign}})$으로 구현. $\text{LUT}_{\text{sign}}$은 부호 함수를 인코딩한다.
    *   **동등 비교 (`==`):** $\text{isEqual}(a, b) \iff a-b=0$. 이는 $\text{PBS}(\text{Enc}(a-b), \text{LUT}_{\text{isZero}})$으로 구현.
    *   **올림/버림/반올림:** $f(x) = x - \frac{1}{2\pi}\sin(2\pi x)$와 같은 주기 함수를 다항식으로 근사하여 반올림 함수를 구현하고, 이를 PBS의 LUT로 사용한다.[27, 28, 29]
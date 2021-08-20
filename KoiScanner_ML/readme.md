# Machine Learning

## Disclaimer
**This Machine Learning Codes are not fully implemented in the Koi Scanner. However, they do work separately.** 

## Step 1

![1](https://user-images.githubusercontent.com/73679712/130197122-af0a10e9-a06e-4f9d-9a9c-2c21dfefbea6.JPG)

**For the first step in machine learning, we read the csv file that contains malicious and non malicious urls. We then randomized the data for further use.**

## Step 2

![2](https://user-images.githubusercontent.com/73679712/130197656-60590886-f2d5-4796-a6c4-8a58ffb61ea8.JPG)

![Traindata75](https://user-images.githubusercontent.com/73679712/130198265-371822cc-838f-4f13-95a8-9f08d55b3450.JPG)

![Testdata25](https://user-images.githubusercontent.com/73679712/130198336-0873aa55-786c-433d-be62-a343e7cc7e83.JPG)

**Next we split the data into 75% Training Data and 25% Testing Data. With the training data, it will be used to create a trained model that will be used on the testing data to determine how well the trained model can detect urls that are malicious and non malicious.**

## Step 3

![tokenize](https://user-images.githubusercontent.com/73679712/130198386-09699fe6-8182-433d-b4c8-5ed0e58ac1af.JPG)

**Before training the data, we made all the urls lower case. Next we tokenize each url. Tokenization is the process of splitting up the urls into pieces and removing punctuation characters. We then did stemming and used Porter Stammer, which is a famous stemming algorithm to replace all similar words.**

## Step 4

![train1](https://user-images.githubusercontent.com/73679712/130199373-e375c63c-0642-41d1-87fe-d4c2e012f5dd.JPG)

![train2](https://user-images.githubusercontent.com/73679712/130199397-413de075-e707-48d6-b335-0bbf56e92b33.JPG)

![train3](https://user-images.githubusercontent.com/73679712/130199420-be4c201c-2092-42c8-9d6b-7daad54891e9.JPG)

**Bag of Words:** In Bag of words model we find the ‘term frequency’, i.e. number of occurrences of each word in the dataset. Thus for word w,

![1_k5hw9fat8QqCxhslpfyTpw](https://user-images.githubusercontent.com/73679712/130200823-a10059a4-3f76-43fa-b322-c5f8a076cd42.png)
 
**and**

![two](https://user-images.githubusercontent.com/73679712/130200932-4d7625d7-8501-4961-bcad-4dafb6605d10.png)

**TF-IDF:** TF-IDF stands for Term Frequency-Inverse Document Frequency. In addition to Term Frequency we compute Inverse document frequency.

![3](https://user-images.githubusercontent.com/73679712/130201183-9607e9e7-900d-4b30-824d-9681cb1f0c5a.png)

**In this model each word has a score, which is TF(w)xIDF(w). Probability of each word is counted as:**

![4](https://user-images.githubusercontent.com/73679712/130201440-f285e8b1-107b-4d6f-b1c4-a53dfa9b8ed7.png)

![5](https://user-images.githubusercontent.com/73679712/130201459-27bd0ddf-d954-4e23-b227-ef25bb2ef12a.png)

**Additive Smoothing:** If we encounter a word in  In that case P(w) will be 0, which will make the P(spam|w) undefined (since we would have to divide by P(w) which is 0. Remember the formula?). To tackle this issue we introduce additive smoothing. In additive smoothing we add a number alpha to the numerator and add alpha times number of classes over which the probability is found in the denominator.

![6](https://user-images.githubusercontent.com/73679712/130205238-a8bdfaa5-8a45-4a9f-992d-6abea6fed6db.png)

**When using TF-IDF**

![7](https://user-images.githubusercontent.com/73679712/130205334-6ffe2472-298b-454b-abfc-9dd5f64edcea.png)


![train4](https://user-images.githubusercontent.com/73679712/130199443-846d70b4-8884-496d-a520-34b8ad49507d.JPG)

**For classifying a given message, first we preprocess it. For each word w in the processed messaged we find a product of P(w|spam). If w does not exist in the train dataset we take TF(w) as 0 and find P(w|spam) using above formula. We multiply this product with P(spam) The resultant product is the P(spam|message). Similarly, we find P(ham|message). Whichever probability among these two is greater, the corresponding tag (spam or ham) is assigned to the input message. Note than we are not dividing by P(w) as given in the formula. This is because both the numbers will be divided by that and it would not affect the comparison between the two.**

## Step 5 

![prediction](https://user-images.githubusercontent.com/73679712/130205557-d00b40ee-b3b7-4272-ad5c-5ce66dbd7e65.JPG)

**Finally after we have finished training the model, we can see the results that shoows the precision and accuracy of the trianed model in detecting malicious and non malicious urls**



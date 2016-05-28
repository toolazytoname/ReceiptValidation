# ReceiptValidation
code for this site https://www.objc.io/issues/17-security/receipt-validation/

在集成OpenSSL的过程中走了一点弯路，上官网下了源码，用本地的Clang打包编译，后来发现直接用Cocoapods 就轻松搞定。

大部分代码都是照抄，C确实太不熟悉了。是不是该好好看看书了。自己费劲加了  
  In-App Purchase Receipt Fields 里面内容的解析，大概意思就是按照这张图的Payload部分，我加的部分代码，正好是In-App Purchase Receipt,这一白色矩形部分。
  
  ![Structure of a receipt](https://developer.apple.com/library/ios/releasenotes/General/ValidateAppStoreReceipt/Art/InAppReceipts_2x.png)
  
  其实我写完代码了，对这个指针语法，还不是太清晰，完全只是机械的模仿，搞定的。
  

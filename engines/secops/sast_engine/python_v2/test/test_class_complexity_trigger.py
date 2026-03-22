# Test script to trigger the cyclomatic_complexity_of_classes_should_not_be_too_high rule

class BigClass:
    def method1(self):
        if self.attr1:
            self.method2()
        else:
            self.method3()
        for i in range(5):
            if i % 2 == 0:
                self.method3()
    def method2(self):
        if self.attr2:
            pass
        else:
            self.method4()
        while self.attr2:
            self.method3()
    def method3(self):
        self.attr3 = 42
    def method4(self):
        for i in range(10):
            self.attr4[i] = i**2
        try:
            x = 1 / 0
        except Exception:
            pass

class SmallClass:
    def method1(self):
        self.attr1 = 42

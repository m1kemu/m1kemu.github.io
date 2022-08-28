---
layout: page
title: "On Writing Offsec Tools in Go"
categories: security
published: true
date: 2022-08-28
---

# On Writing Offsec Tools in Go 
As of late, a large portion of my day-to-day work as a Red Teamer has been devoted to developing custom tools. A lot of factors contribute to me developing offensive security tools myself rather than using pre-built tools (open source or commercial), but it mainly boils down to the following reasons:
- **Evasion**: Pre-built tools are well signatured by security controls. Writing custom tools has always proven to be a reliable means of evading defenses, even if the custom tools closely resemple widely used alternatives.
- **Budget**: The members of the Red Team are the greatest asset for the team, and having the ability to develop tools rather than purchase them or spend cycles configuring badly written alternatives helps limit spending budget on commerical tools and developers.
- **Unique use cases**: While it's not often that a tool does not exist for a task during an engagement, it is often that the tool I find does not exactly fit the bill, or is not performing the task in a way that I think is optimal for the use case. When this happens, I like to write my own rather than spend cycles altering an existing tool. I admit that this might not be the best habit!
- **My enjoyment**: Writing code is fun, and adds an element of creativity to my job.

With that, I have noticed a paradigm shift from writing most of my code in Python to primarily programming in Go. This was a slow transition away from a language that held my heart since highschool, starting with jokes about the inferiority of Go, followed by timid research into the language, then writing simple PoCs in Golang, to finally writing the majority of my code in the language. But why the switch? That is exactly what I intend to discuss.

## Purpose
In this post, I plan on mapping out the reasons why I have moved to using Go as my primary offsec tool programming language. I will provide a brief overview of the Go language, dive into why I enjoy writing code in Go, and talk about instances where I still use Python, C#, or other languages. After this, I will briefly introduce two tools that I have written in Go recently. I don't like to make a post without releasing some type of tool to the community. My hope is that, you (the reader), gains some insight into the advantages of writing offsec tools in Go, and that you find the tools I am releasing alongside this post useful.

Note: This is a less-technical, more narrative style post. I am trying to break the habit of writing monumental, multi-month long technical blog posts that usually never see the light of day, but to rather post what I am thinking, working on, or generally find interesting. 


## Golang Overview
[The Go programming language](https://go.dev/) (Golang) is a compiled programming language created by Google in 2007, motivated by a shared dislike for C++. Go was designed to incorporate some of the design team's [favorite features](https://en.wikipedia.org/wiki/Go_(programming_language)) from other languages, namely:
1. Static typing
2. Readability
3. High performance networking and multiprocessing 

Oddly enough, I wasn't aware of this history until writing this blog post, despite the similarities of the above features and my reasons for writing tools in Go.


## Why Golang 
So, with the background information covered, why have I (and a swath of other security folks) switched to writing tools primarily in Go?

### Simple Code Format
Golang is easy to read, easy to write, and doesn't sacrifice features for the sake of a simplified code format. Here are some example code comparisons involving Golang, Python, and C++. I'll let the code speak for itself!

**Web download**
```golang
req, _ := http.NewRequest("GET", "http://blog.m1kemusec.com", nil)
client := &http.Client{}
resp, _ := client.Do(req)

defer resp.Body.Close()

content, _ := ioutil.ReadAll(resp.Body)
```

**Concurrent printing**
```golang
func GoRoutinePrint() {
        for i := 0; i < 10; i++ {
                fmt.Println(i)
        }

        wg.Done()
}

var wg sync.WaitGroup

func main() {
        wg.Add(5)

        for i := 0; i < 10; i++ {
                go GoRoutinePrint()
        }

        wg.Wait()
}
```


### Ease of Compilation
Compiling code for different platforms is dead simple in the Go programming language, and the output from compilation is reliable. What I mean by this is, I have yet to hit a snag when compiling a golang binary and running it on a target platform (for example, an error related to a third party library when using pyinstaller on a python script or a .NET version error when running a compiled C# script on a target). An example compilation is provided below, but deeper information can be found [here](https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04).

**compiling for windows**
```
env GOOS=windows GOARCH=amd64 go build -o=go_examples.exe ./go_examples.go
```


### Cross Platform
Golang code can run on a vast array of different operating systems and platforms without much hassle. Of course, with OS-specific third party libraries and functionalities this becomes less of a selling point, but generally I don't have issues running the same code on a Linux and Windows host (the primary OS that I use). As of now, Go code can be run on the following OS:
- android
- darwin
- dragonfly
- freebsd
- linux
- netbsd
- openbsd
- plan9
- solaris
- windows

This is great for offensive tooling that performs OS-agnostic functionality. For example, I've written a host recon tool that gathers system data for both Linux and Windows systems that can be cross-compiled easily and runs without issue from a standalone binary. I suppose this is possible in other languages, but Golang makes it *very easy*.

### Concurrency
[Goroutines](https://gobyexample.com/goroutines) are a simple way of incorporating concurrency into code without having to manage the complexity of threads like you would in Python, C++, or other languages. Offensive tool developers can right really fast scanners/fuzzers, conccurent C2 servers, and other awesome tools without hassle thanks to Goroutines and other useful functions like [waitgroups](https://gobyexample.com/waitgroups). This is why I often find myself using Go when writing "high performance" code.


### Third Party Libraries
After spending years writing code in Python, where there is a library for every need you could have, I was not optimistic about finding such an ecosystem in another language. Luckily, Go has a ton of native libraries ("packages" in Go) that get you far enough and there's no shortage of third party packages to allows you to reuse code and develop fast. An importing packages is as easy as running a "go get" and adding the package to your list of imports.

See for yourself! [Run a few searches in the Go package search page](https://pkg.go.dev/).


## When I Avoid Go 
If it isn't obvious, my workflow involves using Python and Go almost exclusively for tool development. I find myself mentally meandering through a decision tree of sorts when I choose which language to choose for a project or component of a project. It looks something like this.

![my_thought_process]("/assets/images/writing_go_code_1.png")


## Conclusion
The Go programming language is, in my opinion (take that for what it's worth!), one of the best tools in an offensive security proffessional's kit. It is a simple, beautiful, fully featured, cross-platform, and high performance language that lends well to tons of security use cases. In fact, as of writing this very paragraph, I have seen several recent articles about threat actors adopting tools written in Go as part of their toolkit.

*P.S: For those interested, I have included links to two recent Golang-based offsec tools that I am currently developing and pushing to a public repository. Enjoy!*  
*P.P.S: These projects are all ongoing efforts, and features may not work 100% correctly!*

With that, **thanks for reading!**


### GoPayloadDropper
This is a weaponized version of a payload launcher that I have used on several campaigns with success. GoPayloadDropper implements payload encryption, decryption, encoding, download, and execution methods into a tool for generating payload droppers for EDR/AV evasion. [More details are available on GitHub]().


### GoEgressChecker
GoEgressChecker is a concurrent, simple egress testing utility to assess ways of exfilrating data from a network, conducting C2, etc. There are several other projects that do the same type of assessing, but none that fit the exact use and as I was aiming for that were written in Golang. [Check it out!]()



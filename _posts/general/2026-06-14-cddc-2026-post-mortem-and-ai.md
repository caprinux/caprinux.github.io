---
title: Reflections of CDDC 2026 and my thoughts on AI in CTFs
description: cddc reflections
date: 2026-06-11 20:00:00 +0800
categories: [general]
tags: [ai]
toc: True
---

This year marks my fifth year playing in Cyber Defender's Discovery Camp (CDDC), **the largest-scale jeopardy CTF in Singapore**, organized by [DSTA](https://dsta.gov.sg).

## CDDC over the years

Allow me to reminisce

**2021** was the year when I first stepped into anything tech and cyber related, to be greeted by this [mess of a CDDC](https://n00bcak.github.io/writeups/2021-06-26-CDDC-2021.html) to set my expectations for my first CDDC ever. That set the bar pretty low.

**2023** was when I competed in the pre-university category with my NS mates, and we did not do too well. Gating challenges that are unrelated to each other behind one another was a horrible experience, I remember barely having time to attempt the pwn challenges because they were blocked by a blackbox web challenge.

**2024** was when I participated in the University category and won for the first time. Thinking back, I really missed the experience of solving those challenges fully manually. Being fully immersed in the technical depths of a challenge to come up with creative solutions to tackle unique problems. _(Thinking back about this, this is probably the thing I miss most about the pre-AI world, and it's the source of my disillusionment with AI.)_

**2025** was when **AI slowly started to become part of the game**, helping to one-shot a few challenges and assisting the participants in a few more. However, most of the challenges still required a significant amount of raw skill and domain knowledge to solve and pull ahead. _This was when AI was still extremely prone to hallucination and was unreliable for anything complex._

Since CDDC 2025, agentic LLMs have come a long way. The capabilities and intelligence of frontier models has grown so exponentially, and the changes that it brought about has become quite extreme today.

## Thoughts on AI in CTFs

> Here goes my rather unorganized rant on AI in CTFs. I'm actually surprised I never wrote about this earlier.

> **Jeopardy CTF challenges with difficulties targeted for the average intelligence of an audience consisting of university and pre-university students will always be trivially solved by frontier AI.**
> Of course, that's provided the challenge has a reasonable solution in the first place. 
{:.prompt-tip}

This is my take on AI capabilities in CTFs, and that's not to say that the target audience is stupid.

CTF challenges typically cover a wide set of skills and knowledge. Even within the individual categories, there are so many different types of commonly used and even obscure technologies that could be covered. The beauty of it has always been that the participants will have to learn how to learn quickly and adapt to an ever-changing set of questions, a very apt reflection of the dynamic cybersecurity industry.

The fact is that when it comes to consuming knowledge at scale and being a domain expert in all kinds of technologies, techniques and algorithms, humans cannot simply compete with a machine that has been trained on most of the internet.

### Pay to win?

Without surprise, any team that did not have a subscription to a frontier AI model was already out of the race.

To even stand a chance at competing, you'd probably want to own one of these subscriptions, or both, which cost around S$300 each. 

- Claude Max x20
- ChatGPT Pro x20

As pricey as this might sound to some, if you have a use case for it, the value easily outweighs the cost of the AI subscription. However, if you were to look at [the profitability of AI](https://isaiprofitable.com/), we can see that frontier AI companies are all operating at a loss. Barring any crazy technological advancements to cut down the cost of AI drastically, this is probably not a sustainable pricing model.

_To put it into perspective --- 20x AI subscription for $300 on Claude/ChatGPT today could easily get you ~$2000 worth of API usage._

### How to win a CTF?

For the unaware, without needing to leave your terminal much, this is how most of the challenge solving process for most CTFs _(and certainly CDDC)_ looked like.

1. Give your agent the CTF credentials, and then ask it to scrape the challenges for you.
2. For each challenge, spin up a new terminal.
3. Run and tell your agent "solve this ctf challenge", or even better "/goal solve this ctf challenge"
4. Wait for the agents to finish
    - When it's stuck and is unable to solve the challenge, ask it to "keep trying"
    - When it has solved the challenge, submit the flag
5. Repeat step 4 until you have solved everything

Of course, with more AI, you could further automate much of this.

However, if everyone is doing the same thing, what determines who wins?

### The randomness of AI agents, aka Temperature

If your agent fails to solve a challenge, you might ask your friend how they did it _(after the CTF)_ and realize that their agent succeeded despite them not doing anything differently from you.

AI agents are not deterministic. You could perhaps run 10 agents on the same challenge, and only some of them would solve it while the others would get stuck.

At the end of the day, this resulted in many people lamenting post-CTF that they were unlucky while the winners might feel that they just got lucky.

**Does that mean that it all comes down to luck?**

### Clanking better

Perhaps, if you're lucky, your agent could solve challenges faster than others. If you're unlucky, you might find your agent wasting time doing the following

- being stuck in a red herring
- running stego tools on the image files in a web challenge
- enumerating the server to find other ports when it's stuck _(and end up finding other challenges and solving them instead)_ 😂
- looking for writeups for the challenge
- and so on...

This is why there is value in writing an [LLM orchestrator](https://aimultiple.com/llm-orchestration) to manage your agents to keep them on track. If your AI subscription permits, you could spin up multiple agents concurrently to race to solve the challenge and overall improve your chances of solving the challenge. Taking it one step further, you could also consider allowing your agents to communicate with each other, sharing progress notes and challenge breakthroughs - which might come in useful when working on more complex challenges.

A major flaw of AI models is that it only knows things up to its knowledge cut-off date, and it does not know about recent things which might cause it to use outdated techniques to tackle certain problems. This is where I find it useful to introduce a **researcher agent** whose job is just to review the progress of existing agents and search the internet for any useful documented vulnerabilities and techniques that might be able to help the agents find a breakthrough and solve the challenge.

Creating an orchestrator to piece together all these small improvements to automate CTF solving in the fastest time possible is quite a fun project, and it really allows you to understand the strengths and flaws of an AI agent, and how to instrument it to make it less flawed. I highly recommend trying to vibecode a CTF orchestrator just to play around with AI. If you're interested, here's [mine](https://github.com/NUSGreyhats/ctf-agent-orchestrator-public).

---

At the end of the day, **we are just consumers of frontier AI models**. Perhaps when it comes to such processes, the frontier AI models probably account for 99% of the work and we are just chasing after that 1% to try to get a small competitive edge over the other teams.

But definitely, I think that these problems are extremely interesting to tackle in today's context -- how to make agents perform better in frontier tasks such as vulnerability research, despite using the same models as your competitors.

At the end of the day, only by first using such models yourself would you be able to gain insight into the strengths and flaws of such agents and come up with creative solutions _(there is no one correct answer)_ on how to make the process better.

### The unfortunate analogy of CTFs in a post-AI world

I would like to draw upon an analogy that I commonly see within the international CTF community lately.

![](https://www.informationdifference.com/wp-content/uploads/token-slot-machines.jpg)
_solving a CTF challenge is like playing a slot machine_

With the use of LLM tokens _(paid for with real money)_, we run the agents _(like pulling the slot machine lever)_ in hopes that it solves the CTF challenge _(like hitting a jackpot)_. If it doesn't work, we can just keep getting the agent to "keep going" until we eventually win.

The analogy of a jackpot mimics the reality of how random the agents can be and how the challenge solving experience has degraded into watching and praying, throwing money/tokens at the challenge until it is solved.

### The diminishing human role in solving challenges

If you've been playing CTFs recently, it is likely that you might find yourself a victim of coming out of the CTF not truly knowing what most of the CTF challenges are about.

As AI agents become increasingly intelligent, it is a natural reaction for us humans to start delegating more of our thinking to these agents. After all, it is in our nature to always take the path of least resistance to get things done, but at what cost?

During CDDC, one of my friends in the organizing team observed my successful exploit on the kernel pwn challenge and asked _"How much of the challenge was done by you?"_ and my answer to him was: _"I have no idea what the challenge is about. Where got time?"_.

Unfortunately, this has become the reality of the game if you're playing to win. You delegate the agents to autonomously solve as much as you can, and you try to steer those that are stuck (or spin up more agents to work on it).

### What's the point of CTFs in the first place?

From the very start, the spirit of CTFs has been to provide a fun and competitive environment for people to learn about deep-tech skills in cybersecurity.

While naysayers might complain that these skills are not directly applicable to many real-world jobs, I can confidently say that strong CTF players will almost certainly make capable technical workers, given their learning ability, critical thinking and problem-solving capabilities. That said, the converse is not necessarily true: someone does not need to be a strong CTF player to be a skilled technical worker.

For me, the goal for CTFs have always been:

1. Having fun.
2. Learning to learn and having a solid technical foundation to be easily able to pick up new technologies on the go.
3. Keeping up with technology - learning about new technologies and picking up and using new exploits, techniques, and tools to solve complex problems.
4. Knowledge sharing within the community, teaching and learning from each other.
5. The friends made along the way.
6. Being a noob-friendly entry point into cybersecurity

Another interesting read is ["CTFs Are not Dead, They're Just Growing Up"](https://caverav.cl/posts/ctfs-not-dead/ctfs-not-dead/).

### Should we then ban AI from CTFs?

I don't have an answer to this question, but I will share some of my thoughts on both sides of the coin.

For online CTFs --- In the same way that we cannot enforce team sizes in an online CTF -- which is why most online CTFs have an unlimited team-size -- we also cannot enforce the use of AI in these online CTFs.

For offline CTFs --- There are more ways to enforce a ban on AI, but still not fool-proof. However, even before AI, there is no fool-proof way for us to prevent people from flag-sharing or getting remote help. Hence I feel like we should not treat it so differently.

--

I think there is value in both allowing AI in CTFs and also banning AI in CTFs _(ignoring the question on how it will be enforced)_.

- Clanking to learn how to better instrument and orchestrate AI agents to outperform other agents. Keep up with the times and learn to better instrument and embrace agentic AI.
- Working on the CTF challenges and solving the problems myself to hone my technical expertise and problem-solving skills

A friend that organizes a CTF at a tech organization once told me: **"As a frontier tech agency, how can we organize a competition and restrict the use of technology itself?"**. There is much truth to that and entirely avoiding AI is never the solution, but I believe at the end of the day, it comes down to the mindset of each individual to decide what they want to achieve out of competing in such CTFs and make the most out of it.

### The motivation for CTFs, or learning

One of the big questions to ask is: **if AI can solve these challenges, is there any point to learning these skills anymore?** Why would anyone need to know what a buffer overflow is now?

As of now, my answer is a definite **yes**.

1. At a minimum, we should keep up enough to understand what the AI is doing. If I can't even be at that level, then I feel there's no point in doing what I do anymore.
2. I feel like AI agents are still not good enough to produce frontier-level research. It's currently good at employing known and existing techniques, but it still seems to fail at finding creative exploit paths especially when faced with vulnerabilities that have unique limitations.
3. On the bright side, I feel like AI is able to accelerate my learning especially for more unfamiliar topics. It's like having a full-time expert researcher that you can ask questions at any time.

It is in our nature to seek rewards for our efforts. As a competitive person, I have always looked to CTF competitions as a way to grow my skills and competency as I strive towards getting better and competing at higher levels. The rewards are easy to see: solving more complex challenges and getting better placements in CTFs.

With AI, much of this has changed and the "wins" feel more distant than ever. The complex challenges are now easily slopped, and the winners in such CTFs are often people with plenty of AI tokens to spare rather than people who have put in the effort to learn the craft.

The next "win" or "reward" for being technically competent may be in finding complex 0-days that are not already slopped by AI agents, which is quite the demoralizing thought. Sure, finding 0-days has always been a win, but the point is that the smaller wins in between that felt more reachable are now gone. **With this, the discipline demanded in the pursuit of technical competence has become greater than ever.**

### CTFs are but a mirror of the technical challenges within the industry

As gloomy as the CTF scene has become for us CTF players, it is a good reminder that this is not a problem isolated to CTFs alone.

As agentic AI becomes more intelligent, the industry is also struggling to cope with and adapt to the changes brought about by AI. Tech workers scramble to stay relevant [_(or lose their jobs)_](https://www.jobslost.ai/), and corporations continue to mindlessly push to automate more processes and produce more AI-powered products.

I'd like to share this blog post I've read recently about how a software engineer's edge over AI has come down to "taste" which I thought was quite an interesting read since we're talking about AI in the industry --- ["LLMs are eroding my software engineering career and I don't know what to do"](https://human-in-the-loop.bearblog.dev/llms-are-eroding-my-software-engineering-career-and-i-dont-know-what-to-do/).

### The end

While it is saddening to see the CTF scene as we know it change so abruptly, this shift is not happening in isolation and is reflected by a much larger transformation in the technical world.

To existing CTF players that feels displaced by these changes, hopefully some of the thoughts will resonate with you and that you will be able to ride the AI wave to become more competent before.

To new CTF players brought in by the AI wave, I hope you slow down from time to time to appreciate the technical complexity and rigour behind these challenges. Do not let CTFs become a black box where AI produces flags and you move on. Take the time to understand the ideas, the constraints, and the craft behind the solution.
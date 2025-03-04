# Link Game
This started as a fun experiment to see how good of a web framework I could create in pure C. It's nowhere near as good as Ruby on Rails, but it still turned out to be pretty ergonomic!
I used it to make a fun little website/social experiement to run at my school.

# How it Works
Upon visiting the [website](https://links.case.edu) (only accessible while on-campus and connected to CWRU wireless network) users are prompted to authenticate via
SSO using their CWRU id. Each user has a unique "invite URL" that they can share with other students, who in turn each get their own unique invite URL, etc. If you
get a faculty member to join using your link you get 5 points, while regular students only give you 1 point. If someone gets Eric Kaler (the university president) to join
using their link, they get 100 points. (UPDATE: someone actually got the president lmfao, was not expecting that to happen).

The homepage looks like this:<br>
![image](https://github.com/user-attachments/assets/0bedb22b-da16-4236-990f-6a843825301b)

There's also a page that renders a pretty nifty interactive graph of everyone participating and the people they've invited:<br>
![image](https://github.com/user-attachments/assets/562d6bd1-4444-492e-89d8-21a88d840584)

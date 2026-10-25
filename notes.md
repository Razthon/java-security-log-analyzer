Open the file

For every line:
    Increase total events

    If line contains INFO:
        increase INFO count

    If line contains WARN:
        increase WARN count

    If line contains ERROR:
        increase ERROR count

    If line contains "Failed login":
        increase failed-login count

Print results
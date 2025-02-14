document.addEventListener("DOMContentLoaded", () => {
    gsap.from(".hero-content", { opacity: 0, y: -60, duration: 1, ease: "power2.out" });
    gsap.from(".step, .benefit", { opacity: 0, y: 40, duration: 1, stagger: 0.3, ease: "back.out(1.7)" });
    gsap.from(".testimonial", { opacity: 0, x: -60, duration: 1, stagger: 0.3, ease: "power2.out" });

    // Smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener("click", function(e) {
            e.preventDefault();
            gsap.to(window, {duration: 1, scrollTo: this.getAttribute("href"), ease: "power2.inOut"});
        });
    });

    // Testimonial slider drag
    const testimonials = document.querySelector(".testimonial-slider");
    let isDown = false, startX, scrollLeft;
    testimonials.addEventListener("mousedown", (e) => {
        isDown = true;
        testimonials.classList.add("active");
        startX = e.pageX - testimonials.offsetLeft;
        scrollLeft = testimonials.scrollLeft;
    });
    testimonials.addEventListener("mouseleave", () => { isDown = false; testimonials.classList.remove("active"); });
    testimonials.addEventListener("mouseup", () => { isDown = false; testimonials.classList.remove("active"); });
    testimonials.addEventListener("mousemove", (e) => {
        if (!isDown) return;
        e.preventDefault();
        const x = e.pageX - testimonials.offsetLeft;
        const walk = (x - startX) * 3;
        testimonials.scrollLeft = scrollLeft - walk;
    });
});
